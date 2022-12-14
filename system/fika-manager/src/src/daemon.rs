use anyhow::{anyhow, Result};
use clap::Args;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
//use tracing_futures::WithSubscriber;
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio::sync::{/*broadcast, Notify,*/ mpsc, oneshot};
use tokio::time::{self, Duration, Instant};
use tracing::{debug, error, info, instrument, warn};
//use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
//use bytes::Bytes;
use std::iter::repeat_with;
//use futures_util::stream::stream::StreamExt;
//use futures_util::StreamExt as _;
use chrono::prelude::*;
use process_stream::StreamExt;
use std::collections::HashMap;
use std::path::PathBuf;
//use std::io;

use crate::publish_task::{publish_main, spawn_task_run_path_publish};
use crate::subscribe_task::{subscribe_ipc_post, subscribe_ipc_register, subscribe_main};
use fika_utils::{
    aws_iot::{mqtt_dedicated_create_start, mqtt_ipc_post, mqtt_ipc_register, AwsIotCmd},
    kap_daemon::KdaemonConfig,
    kap_rule::RuleConfig,
    rule_config_load, setup_logging, DbCommand, RuleConfigTask, SubscribeCmd,
};

#[derive(Debug, Args)]
#[clap(
    args_conflicts_with_subcommands = true,
    about = "core daemon to interactive with platform"
)]
pub struct DaemonOpt {
    #[clap(short = 'c', long = "config", default_value = "/userdata/kdaemon.toml")]
    config: String,
    #[clap(
        short = 'r',
        long = "rule",
        default_value = "/etc/fika_manager/rule.toml"
    )]
    rule: String,
    #[clap(long = "log-level", default_value = "info")]
    log_level: String,
}

#[derive(Debug)]
#[allow(dead_code)]
struct State {
    //publish_conn: redis::aio::Connection,
    //pubsub_conn: redis::aio::PubSub,
    cfg: KdaemonConfig,
    rule: RuleConfig,
}

async fn _conn_rpc_init(
    url: String,
    shared: Arc<Mutex<State>>,
) -> (
    Option<redis::Client>,
    Option<redis::aio::PubSub>,
    Option<redis::aio::PubSub>,
) {
    if let Ok(cacher) = redis::Client::open(url) {
        //let mut conn = cacher.get_async_connection().await?;

        let aws_conn = if let Ok(aws_conn) = cacher.get_async_connection().await {
            let mut aws_conn = aws_conn.into_pubsub();
            if mqtt_ipc_register(&mut aws_conn).await.is_err() {
                warn!("mqtt ipc register fail");
            }
            Some(aws_conn)
        } else {
            None
        };

        let subscribe_conn = if let Ok(subscribe_conn) = cacher.get_async_connection().await {
            let mut subscribe_conn = subscribe_conn.into_pubsub();
            if wrap_subscribe_ipc_register(shared, &mut subscribe_conn)
                .await
                .is_err()
            {
                warn!("subscribe-task ipc register fail");
            }
            //let mut subscribe_stream = subscribe_conn.on_message();
            Some(subscribe_conn)
        } else {
            None
        };

        (Some(cacher), aws_conn, subscribe_conn)
    } else {
        (None, None, None)
    }
}

async fn conn_access_task(
    url: String,
    mut chan_rx: mpsc::Receiver<DbCommand>,
    shared: Arc<Mutex<State>>,
    aws_ipc_tx: mpsc::Sender<AwsIotCmd>,
    subscribe_ipc_tx: mpsc::Sender<SubscribeCmd>,
) -> Result<()> {
    let cacher = redis::Client::open(url);
    if let Err(e) = cacher {
        error!("[rpc-core] redis client open fail - {:?}", &e);
        return Err(anyhow!("[rpc-core] client open {:?}", e));
    }

    let cacher = cacher.unwrap();
    let conn = cacher.get_async_connection().await;
    if let Err(e) = conn {
        error!("[rpc-core] redis async connection fail - {:?}", &e);
        return Err(anyhow!("[rpc-core] async connection {:?}", e));
    }

    let mut conn = conn.unwrap();
    let aws_conn = cacher.get_async_connection().await;
    if let Err(e) = aws_conn {
        error!("[rpc-core] aws redis async connection fail - {:?}", &e);
        return Err(anyhow!("[rpc-core] aws async connection {:?}", e));
    }
    let mut aws_conn = aws_conn.unwrap().into_pubsub();

    if let Err(e) = mqtt_ipc_register(&mut aws_conn).await {
        error!("[rpc-core] mqtt/ipc register fail - {:?}", &e);
        return Err(anyhow!("[rpc-core] mqtt/ipc register fail {:?}", e));
    }
    let mut aws_stream = aws_conn.on_message();

    let subscribe_conn = cacher.get_async_connection().await;
    if let Err(e) = subscribe_conn {
        error!(
            "[rpc-core] subscribe redis async connection fail - {:?}",
            &e
        );
        return Err(anyhow!("[rpc-core] subscribe async connection {:?}", e));
    }
    let mut subscribe_conn = subscribe_conn.unwrap().into_pubsub();

    if let Err(e) = wrap_subscribe_ipc_register(shared, &mut subscribe_conn).await {
        error!("[rpc-core] subscribe/ipc register fail - {:?}", &e);
        return Err(anyhow!("[rpc-core] subscribe/ipc register fail {:?}", e));
    }
    let mut subscribe_stream = subscribe_conn.on_message();

    loop {
        tokio::select! {
            cmd = chan_rx.recv() => {
                if let Some(cmd) = cmd {
                    match cmd {
                        DbCommand::Get { key, resp } => {
                            let value: Option<String> = conn.get(key).await.ok();
                            //info!("[conn_access_task]: todo {}", value);
                            let _ = resp.send(value);
                        }
                        DbCommand::Set { key, val, resp } => {
                            let ret: Option<String> = conn.set(key, val).await.ok();
                            //debug!("[conn_access_task]: todo {}", ret);
                            let _ = resp.send(ret);
                        }
                        DbCommand::Publish { key, val, resp } => {
                            let ret: Option<usize> = conn.publish(key, val).await.ok();
                            //debug!("[conn_access_task]: todo {}", ret);
                            let _ = resp.send(ret);
                        }
                        DbCommand::Lindex { key, idx, resp } => {
                            let value: Option<String> = conn.lindex(key, idx).await.ok();
                            //info!("[conn_access_task]: todo {}", value);
                            let _ = resp.send(value);
                        }
                        DbCommand::Rpush { key, val, limit } => {
                            if let Ok(len) = conn.rpush::<&str, String, usize>(&key, val).await {
                                if len == limit {
                                    if let Err(e) = conn.lpop::<&str, String>(&key, None).await {
                                        return Err(anyhow!("DB RPUSH/LPOP fail - {:?}", e));
                                    }
                                }
                            }
                        }
                        /*DbCommand::AwsShadowPublish { key, val } => {
                            let r = aws_ipc_tx.clone().send(AwsIotCmd::ShadowUpdate {
                                topic: key,
                                msg: val,
                            }).await;
                            if r.is_err() {
                                error!("ipc/AwsShadowPublish => aws send fail - {:?}", r);
                            } else {
                                debug!("ipc/AwsShadowPublish => aws send success - {:?}", r);
                            }
                        }
                        DbCommand::NotifySubscribe { key } if sub_done == false => {
                            let r = subscribe_conn.subscribe(&key).await;
                            if r.is_err() {
                                error!("ipc/NotifySubscribe => aws send fail - {:?}", r);
                            } else {
                                debug!("ipc/NotifySubscribe => aws send success - {:?}", r);
                            }
                        }*/
                        DbCommand::Exit => {
                            break;
                        }
                    }
                }
            },
            msg = aws_stream.next() => {
                let r = mqtt_ipc_post(aws_ipc_tx.clone(), msg).await;
                if r.is_err() {
                    error!("ipc/psubscribe => aws send fail - {:?}", r);
                } else {
                    debug!("ipc/psubscribe => aws send success - {:?}", r);
                }
            },
            msg = subscribe_stream.next() => {
                let r = subscribe_ipc_post(subscribe_ipc_tx.clone(), msg).await;
                if r.is_err() {
                    error!("ipc/subscribe => sub-proc send fail - {:?}", r);
                } else {
                    debug!("ipc/subscribe => sub-proc send success - {:?}", r);
                }
            },
        }
    }

    Ok(())
}

async fn wrap_subscribe_ipc_register(
    shared: Arc<Mutex<State>>,
    sub: &mut redis::aio::PubSub,
) -> Result<()> {
    let sub_list: Option<Vec<String>>;
    {
        let state = shared.lock().unwrap();
        let sub_ref = state.rule.subscribe.as_ref();

        sub_list = sub_ref
            .as_ref()
            .map(|v| v.iter().map(|e| e.topic.clone()).collect());
    }
    subscribe_ipc_register(sub, sub_list).await?;

    Ok(())
}

//#[instrument(skip(subscribe_rx, shared))]
async fn subscribe_task(
    subscribe_rx: mpsc::Receiver<SubscribeCmd>,
    chan_tx: mpsc::Sender<DbCommand>,
    shared: Arc<Mutex<State>>,
) -> Result<()> {
    //let subscribe;
    let mut entries: HashMap<String, PathBuf> = HashMap::new();
    {
        let state = shared.lock().unwrap();
        if let Some(sub_ref) = state.rule.subscribe.as_ref() {
            for ss in sub_ref {
                debug!("subscribe-task entry insert {:?}", &ss);
                entries.insert(ss.topic.clone(), ss.path.clone());
            }
        }
    }
    subscribe_main(subscribe_rx, chan_tx, entries).await?;
    /*if let Some(vs) = subscribe {
        for ss in vs {
            debug!("subscribe-task entry insert {:?}", &ss);
            entries.insert(ss.topic, ss.path);
        }

        subscribe_main(subscribe_rx, chan_tx, entries).await?;
    }*/
    Ok(())
}

#[instrument(
    //level = "info",
    name = "publish::task",
    skip_all,
)]
async fn publish_task(
    chan_tx: mpsc::Sender<DbCommand>,
    aws_ipc_tx: mpsc::Sender<AwsIotCmd>,
    shared: Arc<Mutex<State>>,
) -> Result<()> {
    let mut entries: HashMap<String, RuleConfigTask> = HashMap::new();
    if let Ok(state) = shared.lock() {
        if let Some(ps) = &state.rule.task {
            for p in ps {
                entries.insert(p.topic.clone(), p.clone());
            }
        }
    }

    publish_main(chan_tx, aws_ipc_tx, entries).await
}

#[allow(dead_code)]
async fn test_task(chan_tx: mpsc::Sender<DbCommand>, _shared: Arc<Mutex<State>>) -> Result<()> {
    loop {
        let v = vec![1, 2, 3];
        let i = fastrand::usize(..v.len());
        let elem = v[i];

        if elem == 1 {
            let (resp_tx, resp_rx) = oneshot::channel();

            chan_tx
                .send(DbCommand::Set {
                    key: String::from("test"),
                    val: repeat_with(fastrand::alphanumeric).take(10).collect(),
                    resp: resp_tx,
                })
                .await?;

            let res = resp_rx.await;
            info!("[test_task][Set] got response {:?}", res);
        }
        if elem == 2 {
            let (resp_tx, resp_rx) = oneshot::channel();

            chan_tx
                .send(DbCommand::Get {
                    key: String::from("test"),
                    resp: resp_tx,
                })
                .await?;
            let res = resp_rx.await;
            info!("[test_task][Get] got response {:?}", res);
        }
        if elem == 3 {
            let (resp_tx, resp_rx) = oneshot::channel();

            chan_tx
                .send(DbCommand::Publish {
                    key: String::from("hello"),
                    val: String::from("gggg"),
                    resp: resp_tx,
                })
                .await?;
            let res = resp_rx.await;
            info!("[test_task][Publish] got response {:?}", res);
        }

        time::sleep(Duration::from_secs(i as u64)).await;
    }
}

pub async fn daemon(opt: DaemonOpt) -> Result<()> {
    setup_logging(&opt.log_level)?;

    let (rule, cfg) = rule_config_load(&opt.rule, Some(&opt.config)).await?;
    cfg.config_verify().await?;

    let (chan_tx, chan_rx) = mpsc::channel::<DbCommand>(32);
    let (aws_ipc_tx, aws_ipc_rx) = mpsc::channel::<AwsIotCmd>(32);
    let (subscribe_tx, subscribe_rx) = mpsc::channel::<SubscribeCmd>(32);

    let url = rule.core.database.as_ref().unwrap().clone();
    let shared = Arc::new(Mutex::new(State { cfg, rule }));

    let _conn_task = tokio::spawn(conn_access_task(
        url,
        chan_rx,
        shared.clone(),
        aws_ipc_tx.clone(),
        subscribe_tx.clone(),
    ));
    //tokio::spawn(test_task(chan_tx.clone(), shared.clone()));

    let _sub_task = tokio::spawn(subscribe_task(
        subscribe_rx,
        chan_tx.clone(),
        shared.clone(),
    ));
    let _pub_task = tokio::spawn(publish_task(
        chan_tx.clone(),
        aws_ipc_tx.clone(),
        shared.clone(),
    ));
    let _cron_task = tokio::spawn(honest_task(
        chan_tx.clone(),
        aws_ipc_tx.clone(),
        shared.clone(),
    ));
    let _mqtt_task = tokio::spawn(mqtt_task(
        aws_ipc_rx,
        chan_tx.clone(),
        subscribe_tx.clone(),
        shared.clone(),
    ));

    let future_sig_c = signal::ctrl_c();

    tokio::select! {
        _ = future_sig_c => {
            info!("exit by catch signal-c");
        }
    }
    //graceful shudown? tokio::join!();

    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct BossHcsPair {
    hcs_sid: String,
    hcs_token: String,
    init_time: DateTime<Utc>,
    invalid_time: DateTime<Utc>,
}

#[instrument(
    //level = "info",
    name = "honest::task",
    skip_all,
)]
async fn honest_task(
    chan_tx: mpsc::Sender<DbCommand>,
    aws_ipc_tx: mpsc::Sender<AwsIotCmd>,
    shared: Arc<Mutex<State>>,
) {
    let key_hcs_list = "boss.hcs.token.list";
    let mut fail_cycle = Duration::from_secs(10);
    let mut ok_cycle = Duration::from_secs(10);
    let mut cmd_path = PathBuf::from("/etc/fika_manager/boss_token.sh");
    let mut disable = false;
    if let Ok(state) = shared.lock() {
        if let Some(honest) = &state.rule.honest {
            fail_cycle = honest.fail_cycle;
            ok_cycle = honest.ok_cycle;
            cmd_path = honest.path.clone();
            disable = honest.disable.unwrap_or_else(|| false);
        }
    }

    if disable == true {
        info!("internal honest task disable");
        return;
    }

    let mut when = Instant::now() + fail_cycle;

    loop {
        tokio::select! {
            _ = time::sleep_until(when) => {
                if let Ok(job) = spawn_task_run_path_publish(
                    chan_tx.clone(),
                    "boss.token".to_string(),
                    cmd_path.clone(),
                    Some(Duration::from_secs(10)),
                    None, None,
                    None, aws_ipc_tx.clone()) {

                    if !job.is_finished() {
                        _ = job.await;
                    }
                    debug!("job {:?} completed", &cmd_path);

                    let (resp_tx, resp_rx) = oneshot::channel();
                    if let Ok(_) = chan_tx.send(DbCommand::Lindex {
                        key: String::from(key_hcs_list),
                        idx: 0,
                        resp: resp_tx,
                    }).await {
                        if let Ok(Some(res)) = resp_rx.await {
                            if let Ok(boss_hcs) = serde_json::from_str::<BossHcsPair>(&res) {
                                debug!("challenge struct as {:?}", res);
                                let now = Utc::now();
                                if now >= boss_hcs.init_time && now < boss_hcs.invalid_time {
                                    let delta = boss_hcs.invalid_time - now;
                                    when = Instant::now() + delta.to_std().unwrap_or(ok_cycle);
                                    info!("Next refresh cycle at {:?}", when);
                                } else {
                                    when = Instant::now() + ok_cycle;
                                    error!("Older one refresh cycle at {:?}", when);
                                }
                                continue;
                            }
                        }
                    }
                }
                when = Instant::now() + fail_cycle;
                error!("Otherwise rollback refresh cycle at {:?}", when);
            }
        }
    }
}

#[instrument(name = "mqtt::task", skip_all)]
async fn mqtt_task(
    aws_ipc_rx: mpsc::Receiver<AwsIotCmd>,
    db_chan: mpsc::Sender<DbCommand>,
    subscribe_ipc_tx: mpsc::Sender<SubscribeCmd>,
    shared: Arc<Mutex<State>>,
) {
    if let Ok(state) = shared.lock() {
        debug!("aws-iot-config {:?}", state.rule.aws);
    }

    let (kcfg, rule) = if let Ok(state) = shared.lock() {
        (Some(state.cfg.clone()), Some(state.rule.aws.clone()))
    } else {
        (None, None)
    };

    if kcfg.is_none() {
        error!("kdaemon/cmp config not satisfy");
        return;
    }
    let kcfg = kcfg.unwrap();

    if let Some(aws) = rule {
        if let Err(e) = mqtt_dedicated_create_start(
            &kcfg,
            aws,
            aws_ipc_rx,
            db_chan.clone(),
            subscribe_ipc_tx.clone(),
        )
        .await
        {
            error!("MQTT dedicated function not work - {:?}", e);
        }
    };
}
