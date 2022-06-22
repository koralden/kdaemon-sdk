use clap::Parser;
// import tokio fs to read file
use anyhow::Result;
use redis::AsyncCommands;
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use tokio::fs;
use tokio::signal;
use tokio::sync::{/*broadcast, Notify,*/ mpsc, oneshot};
use tokio::time::{self, Duration /*, Instant*/};
use tracing::{debug, error, info /*, instrument*/};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
//use bytes::Bytes;
use std::iter::repeat_with;
//use futures_util::stream::stream::StreamExt;
use futures_util::StreamExt as _;
use process_stream::{Process, StreamExt};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug, Clone)]
#[clap(
    name = "fika-manager",
    about = "FIKA manager to interactive with platform"
)]
struct Opt {
    #[clap(
        short = 'c',
        long = "config",
        default_value = "/etc/fika_manager/config.toml"
    )]
    config: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Config {
    core: ConfigCore,
    subscribe: Option<Vec<ConfigSubscribe>>,
    publish: Option<Vec<ConfigPublish>>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct ConfigCore {
    database: String,
    version: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct ConfigSubscribe {
    topic: String,
    path: PathBuf,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct ConfigPublish {
    topic: String,
    path: PathBuf,
    is_loop: bool,
    period: Option<u32>,
}

#[allow(dead_code)]
struct State {
    //publish_conn: redis::aio::Connection,
    //pubsub_conn: redis::aio::PubSub,
    cfg: Config,
}

#[derive(Debug)]
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
}

async fn conn_access_task(
    mut conn: redis::aio::Connection,
    mut chan_rx: mpsc::Receiver<Command>,
    shared: Arc<Mutex<State>>,
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
        }
    }

    Ok(())
}

async fn subscribe_task(
    mut sub_conn: redis::aio::PubSub,
    chan_tx: mpsc::Sender<Command>,
    shared: Arc<Mutex<State>>,
) -> Result<()> {
    /*let mut backoff = 8;
    loop {
        error!("[subscribe_task] TODO");

        backoff = backoff - 1;
        if backoff == 0 {
            backoff = 8;
        }
        time::sleep(Duration::from_secs(backoff)).await;
    }*/
    let mut subscribe = None;
    {
        let mut state = shared.lock().unwrap();
        /*if let Some(vs) = state.cfg.subscribe.as_ref() {
        //debug!("subscribe {:?}", vs);

        for ss in vs {
        //debug!("subscribe {:?}", ss);
        }
        }

        let subs = state.cfg.subscribe.as_ref();
        if let Some(vs) = subs {
        for ss in vs {
        //debug!("subscribe {:?}", ss);
        //sub_conn.subscribe(&ss.topic).await?;
        }
        }*/
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
                        "[subscribe_task] got msg {:?} => {:?}/{:?} => path-{:?}",
                        msg, topic, payload, path
                    );
                    let mut cmd: Process = path.into();
                    cmd.arg(&payload);

                    let mut cmd_stream = cmd.spawn_and_stream()?;
                    /*TODO, kill long-term job with static timeout */
                    /*let worker_th = */
                    tokio::spawn(async move {
                        while let Some(output) = cmd_stream.next().await {
                            if output.is_exit() {
                                info!("Done");
                            } else {
                                debug!("{output}");
                            }
                        }
                    });
                } else {
                    error!("[subscribe_task] topic-{:?} no path", topic);
                }
            } else {
                error!("[subscribe_task] not topic in msg {:?}!!", msg);
            }
        }
    }
    Ok(())
}

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

    let conn_task = tokio::spawn(conn_access_task(
        cache.get_async_connection().await?,
        chan_rx,
        shared.clone(),
    ));
    //tokio::spawn(test_task(chan_tx.clone(), shared.clone()));

    let sub_task = tokio::spawn(subscribe_task(
        cache.get_async_connection().await?.into_pubsub(),
        chan_tx.clone(),
        shared.clone(),
    ));

    let future_sig_c = signal::ctrl_c();

    //tokio::join!();
    tokio::select! {
        _ = future_sig_c => {
            info!("exit by catch signal-c");
        }
    }

    Ok(())
}
