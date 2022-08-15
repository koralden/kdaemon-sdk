use anyhow::{anyhow, Result};
use clap::Parser;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::fs;
use tokio::signal;
use tokio::sync::{/*broadcast, Notify,*/ mpsc, oneshot};
use tokio::time::{self, Duration, Instant};
use tracing::{debug, error, info, warn, instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
//use bytes::Bytes;
use std::iter::repeat_with;
//use futures_util::stream::stream::StreamExt;
//use futures_util::StreamExt as _;
use process_stream::{Process, ProcessItem, Stream, StreamExt};
use std::collections::{BTreeMap, HashMap};
//use std::io;
use std::path::PathBuf;
use chrono::prelude::*;

#[derive(Parser, Debug, Clone)]
#[clap(
    name = "fika-manager",
    about = "FIKA manager to interactive with platform",
    version = "0.0.2",
)]
struct Opt {
    #[clap(
        short = 'c',
        long = "config",
        default_value = "/etc/fika_manager/config.toml"
    )]
    config: String,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct Config {
    core: ConfigCore,
    subscribe: Option<Vec<ConfigSubscribe>>,
    task: Option<Vec<ConfigTask>>,
    honest: Option<HonestConfig>,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct ConfigCore {
    database: String,
    version: String,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct ConfigSubscribe {
    topic: String,
    path: PathBuf,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
#[allow(dead_code)]
struct ConfigTask {
    topic: String,
    path: PathBuf,
    start_at: Option<Duration>,
    period: Option<Duration>,
    db_publish: Option<bool>,
    db_set: Option<bool>,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct HonestConfig {
    ok_cycle: Duration,
    fail_cycle: Duration,
    path: PathBuf,
}


#[derive(Debug)]
#[allow(dead_code)]
struct State {
    //publish_conn: redis::aio::Connection,
    //pubsub_conn: redis::aio::PubSub,
    cfg: Config,
}

#[derive(Debug)]
#[allow(dead_code)]
enum Command {
    Get {
        key: String,
        resp: oneshot::Sender<Option<String>>,
    },
    Set {
        key: String,
        val: String, //TODO Bytes
        resp: oneshot::Sender<Option<String>>,
    },
    Publish {
        key: String,
        val: String,
        resp: oneshot::Sender<Option<usize>>,
        //resp: mpsc::Sender<Option<String>>,
    },
    Lindex {
        key: String,
        idx: isize,
        resp: oneshot::Sender<Option<String>>,
    },
}

async fn conn_access_task(
    mut conn: redis::aio::Connection,
    mut chan_rx: mpsc::Receiver<Command>,
    _shared: Arc<Mutex<State>>,
) -> Result<()> {
    /*loop {
        time::sleep(Duration::from_secs(backoff)).await;
    }*/
    while let Some(cmd) = chan_rx.recv().await {
        match cmd {
            Command::Get { key, resp } => {
                let value: Option<String> = conn.get(key).await.ok();
                //info!("[conn_access_task]: todo {}", value);
                let _ = resp.send(value);
            }
            Command::Set { key, val, resp } => {
                let ret: Option<String> = conn.set(key, val).await.ok();
                //debug!("[conn_access_task]: todo {}", ret);
                let _ = resp.send(ret);
            }
            Command::Publish { key, val, resp } => {
                let ret: Option<usize> = conn.publish(key, val).await.ok();
                //debug!("[conn_access_task]: todo {}", ret);
                let _ = resp.send(ret);
            }
            Command::Lindex { key, idx, resp } => {
                let value: Option<String> = conn.lindex(key, idx).await.ok();
                //info!("[conn_access_task]: todo {}", value);
                let _ = resp.send(value);
            }
        }
    }

    Ok(())
}

#[instrument(skip(sub_conn, shared))]
async fn subscribe_task(
    mut sub_conn: redis::aio::PubSub,
    _chan_tx: mpsc::Sender<Command>,
    shared: Arc<Mutex<State>>,
) -> Result<()> {
    let subscribe;
    {
        let mut state = shared.lock().unwrap();
        subscribe = state.cfg.subscribe.take();
    }
    if let Some(vs) = subscribe {
        let mut entries: HashMap<String, PathBuf> = HashMap::new();
        for ss in vs {
            //debug!("subscribe {:?}", ss);
            sub_conn.subscribe(&ss.topic).await?;
            entries.insert(ss.topic, ss.path);
        }

        let mut sub_stream = sub_conn.on_message();
        while let Some(msg) = sub_stream.next().await {
            if let Ok(topic) = msg.get_channel::<String>() {
                let payload = msg.get_payload::<String>().unwrap_or("".into());

                if let Some(path) = entries.get(&topic) {
                    debug!(
                        "got msg {:?} => {:?}/{:?} => path-{:?}",
                        msg, topic, payload, path
                    );
                    let mut cmd: Process = path.into();
                    cmd.arg(&payload);

                    if let Ok(cmd_stream) = cmd.spawn_and_stream() {
                        tokio::spawn(async move {
                            let timeout = Duration::from_secs(86400);
                            tokio::select! {
                                Ok(_) = capture_process_stream(
                                    Ok(cmd_stream)) => {}
                                _ = time::sleep(timeout) => {
                                    error!("{} task timeout({:?}) exit", topic, timeout);
                                    cmd.kill().await;
                                }
                                else => {
                                }
                            }
                        });
                    } else {
                        error!("cmd spawn_and_stream error!");
                    }
                } else {
                    error!("topic-{:?} no path", topic);
                }
            } else {
                error!("not topic in msg {:?}!!", msg);
            }
        }
    }
    Ok(())
}

type ExpirationT = BTreeMap<(Instant, u64), (String, Option<Duration>)>;

fn next_topics(expirations: Arc<Mutex<ExpirationT>>) -> Option<(Instant, String)> {
    let mut expirations = expirations.lock().unwrap();

    let expirations = &mut *expirations;
    let now = Instant::now();
    while let Some((&(when, id), (topic, _))) = expirations.iter().next() {
        /* TODO equal case to cover the same start time */
        if when >= now {
            return Some((when, topic.to_string()));
        } else {
            if let Some((topic, Some(period))) = expirations.remove(&(when, id)) {
                let when = now + period;
                expirations.insert((when, id), (topic, Some(period)));
            }
        }
    }
    None
}

#[instrument(skip(chan_tx))]
async fn publish_message(
    chan_tx: mpsc::Sender<Command>,
    topic: String,
    payload: String,
) -> Result<()> {
    let (resp_tx, resp_rx) = oneshot::channel();

    chan_tx
        .send(Command::Publish {
            key: topic.clone(),
            val: payload,
            resp: resp_tx,
        })
        .await?;

    let res = resp_rx.await;
    debug!(
        "[publish_task][publish][{}] transmit response {:?}",
        topic, res
    );

    Ok(())
}

#[instrument(skip(chan_tx))]
async fn set_message(chan_tx: mpsc::Sender<Command>, topic: String, payload: String) -> Result<()> {
    let (resp_tx, resp_rx) = oneshot::channel();

    chan_tx
        .send(Command::Set {
            key: topic.clone(),
            val: payload,
            resp: resp_tx,
        })
        .await?;

    let res = resp_rx.await;
    debug!(
        "[publish_task][publish][{}] transmit response {:?}",
        topic, res
    );

    Ok(())
}

#[instrument(skip(process_stream))]
async fn capture_process_stream(
    process_stream: Result<impl Stream<Item = ProcessItem> + Send + std::marker::Unpin>,
) -> Result<String> {
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit = -1;

    if let Ok(mut cmd_stream) = process_stream {
        while let Some(pi) = cmd_stream.next().await {
            match pi {
                ProcessItem::Exit(e) => {
                    debug!("Exit {e}");
                    exit = e.parse::<i8>().unwrap_or(-1);
                }
                ProcessItem::Error(e) => {
                    debug!("Error {e}");
                    stderr.push_str(&e);
                }
                ProcessItem::Output(o) => {
                    debug!("Output {o}");
                    stdout.push_str(&o);
                }
            }
        }
    } else {
        stderr.push_str(r#"Not Found}"#);
    }

    if exit == 0 {
        Ok(stdout)
    } else {
        Err(anyhow!(stderr))
    }
}

fn spawn_task_run_path_publish(
    chan_tx: mpsc::Sender<Command>,
    topic: String,
    path: PathBuf,
    timeout: Option<Duration>,
    db_publish: Option<bool>,
    db_set: Option<bool>,
) -> Result<tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>> {
    let mut process = Process::new(&path);
    match process.spawn_and_stream() {
        Ok(process_stream) => {
            let job = tokio::spawn(async move {
                let timeout = match timeout {
                    Some(t) => t,
                    None => Duration::from_secs(86400), /* XXX 24h */
                };
                tokio::select! {
                    out = capture_process_stream(Ok(process_stream)) => {
                        match out {
                            Ok(payload) => {
                                if db_publish.is_some() {
                                    publish_message(chan_tx.clone(), topic.clone(), payload.clone()).await?;
                                }
                                if db_set.is_some() {
                                    set_message(chan_tx, topic, payload).await?;
                                }
                            },
                            Err(e) => {
                                error!("process return error-{:?}", e);
                            },
                        }
                    }
                    _ = time::sleep(timeout) => {
                        process.kill().await;
                        warn!("{} task timeout({:?}) exit", topic, timeout);
                    }
                    else => {
                        warn!("else case?");
                    }
                }
                /* help the rust type inferencer out, ref https://tokio.rs/tokio/tutorial/select */
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            });
            Ok(job)
        },
        Err(e) => Err(anyhow!(e)),
    }
}

#[instrument(
    //level = "info",
    name = "publish::task",
    skip(chan_tx, shared),
)]
async fn publish_task(chan_tx: mpsc::Sender<Command>, shared: Arc<Mutex<State>>) -> Result<()> {
    let mut entries: HashMap<
        String,
        (
            PathBuf,
            Option<Duration>,
            Option<Duration>,
            Option<bool>,
            Option<bool>,
        ),
    > = HashMap::new();
    if let Ok(state) = shared.lock() {
        if let Some(ps) = &state.cfg.task {
            for p in ps {
                entries.insert(
                    p.topic.clone(),
                    (p.path.clone(), p.start_at, p.period, p.db_publish, p.db_set),
                );
            }
        }
    }

    //let mut expirations: BTreeMap<(Instant, u64), (String, Option<Duration>)> = BTreeMap::new();
    let mut expirations: ExpirationT = BTreeMap::new();
    let now = Instant::now();
    let mut id = 1;

    for (topic, (path, start_at, period, db_publish, db_set)) in &entries {
        match *start_at {
            Some(start) => {
                let when = now + start;
                debug!(
                    "start_at entries insert {:?} {:?}",
                    (when, id),
                    (topic, period)
                );
                expirations.insert((when, id), (topic.to_string(), *period));
                id = id + 1;
            }
            None => {
                let timeout = match *period {
                    Some(period) => Some(period - Duration::from_millis(100)),
                    _ => None,
                };

                if let Some(period) = *period {
                    let when = now + period;
                    debug!(
                        "period entries insert {:?} {:?}",
                        (when, id),
                        (topic, period)
                    );
                    expirations.insert((when, id), (topic.to_string(), Some(period)));
                    id = id + 1;
                } else {
                    /* run immediately */
                    _ = spawn_task_run_path_publish(
                        chan_tx.clone(),
                        topic.to_string(),
                        path.to_path_buf(),
                        timeout,
                        *db_publish,
                        *db_set,
                    );
                }
            }
        }
    }

    let expirations_cloned = Arc::new(Mutex::new(expirations)).clone();
    tokio::spawn(async move {
        while let Some((when, topic)) = next_topics(expirations_cloned.clone()) {
            tokio::select! {
                _ = time::sleep_until(when) => {
                    if let Some((path, _, period, db_publish, db_set)) =entries.get(&topic) {
                        _ = spawn_task_run_path_publish(
                            chan_tx.clone(),
                            topic.to_string(),
                            path.to_path_buf(),
                            *period,
                            *db_publish, *db_set);
                    }
                }
            }
        }
    });

    Ok(())
}

#[allow(dead_code)]
async fn test_task(chan_tx: mpsc::Sender<Command>, _shared: Arc<Mutex<State>>) -> Result<()> {
    loop {
        let v = vec![1, 2, 3];
        let i = fastrand::usize(..v.len());
        let elem = v[i];

        if elem == 1 {
            let (resp_tx, resp_rx) = oneshot::channel();

            chan_tx
                .send(Command::Set {
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
                .send(Command::Get {
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
                .send(Command::Publish {
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

pub type MyError = Box<dyn std::error::Error + Send + Sync>;
fn set_up_logging(log_level: &str) -> Result<(), MyError> {
    // See https://docs.rs/tracing for more info
    //tracing_subscriber::fmt::try_init()
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(move |_| {
                format!("{},redis={},mio={}", log_level, log_level, log_level).into()
            }),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), MyError> {
    set_up_logging("debug")?;

    let opt = Opt::parse();

    //debug!("config as {}", opt.config);

    let cfg = fs::read_to_string(opt.config).await?;
    let cfg: Config = toml::from_str(&cfg)?;
    //debug!("cfg content as {:#?}", cfg);

    let (chan_tx, chan_rx) = mpsc::channel::<Command>(32);
    //let url: &str = &cfg.core.database;
    let cache = redis::Client::open(&*cfg.core.database)?;
    let shared = Arc::new(Mutex::new(State {
        //publish_conn: cache.get_async_connection().await?,
        //pubsub_conn: cache.get_async_connection().await?.into_pubsub(),
        cfg,
    }));

    let _conn_task = tokio::spawn(conn_access_task(
        cache.get_async_connection().await?,
        chan_rx,
        shared.clone(),
    ));
    //tokio::spawn(test_task(chan_tx.clone(), shared.clone()));

    let _sub_task = tokio::spawn(subscribe_task(
        cache.get_async_connection().await?.into_pubsub(),
        chan_tx.clone(),
        shared.clone(),
    ));
    let _pub_task = tokio::spawn(publish_task(chan_tx.clone(), shared.clone()));
    let _cron_task = tokio::spawn(honest_task(chan_tx.clone(), shared.clone()));

    let future_sig_c = signal::ctrl_c();

    //tokio::join!();
    tokio::select! {
        _ = future_sig_c => {
            info!("exit by catch signal-c");
        }
    }

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
    skip(chan_tx, shared),
)]
async fn honest_task(chan_tx: mpsc::Sender<Command>, shared: Arc<Mutex<State>>) {
    let mut fail_cycle = Duration::from_secs(10);
    let mut ok_cycle = Duration::from_secs(10);
    let mut cmd_path = PathBuf::from("/etc/fika_manager/boss_token.sh");
    if let Ok(state) = shared.lock() {
        if let Some(honest) = &state.cfg.honest {
            fail_cycle = honest.fail_cycle;
            ok_cycle = honest.ok_cycle;
            cmd_path = honest.path.clone();
        }
    }
    let mut when = Instant::now() + ok_cycle;

    loop {
        tokio::select! {
            _ = time::sleep_until(when) => {
                if let Ok(job) = spawn_task_run_path_publish(
                    chan_tx.clone(),
                    "boss.token".to_string(),
                    cmd_path.clone(),
                    Some(Duration::from_secs(10)),
                    None, None) {

                    if !job.is_finished() {
                        _ = job.await;
                    }
                    debug!("job {:?} completed", &cmd_path);

                    let (resp_tx, resp_rx) = oneshot::channel();
                    if let Ok(_) = chan_tx.send(Command::Lindex {
                        key: String::from("boss.hcs.token.list"),
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
