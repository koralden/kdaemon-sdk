use clap::Parser;
use anyhow::{anyhow, Result};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::fs;
use tokio::signal;
use tokio::sync::{/*broadcast, Notify,*/ mpsc, oneshot};
use tokio::time::{self, Duration, Instant};
use tracing::{debug, error, info, instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
//use bytes::Bytes;
use std::iter::repeat_with;
//use futures_util::stream::stream::StreamExt;
//use futures_util::StreamExt as _;
use process_stream::{Process, ProcessItem, Stream, StreamExt};
use std::collections::{BTreeMap, HashMap};
//use std::io;
use std::path::PathBuf;

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

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct Config {
    core: ConfigCore,
    subscribe: Option<Vec<ConfigSubscribe>>,
    publish: Option<Vec<ConfigPublish>>,
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
struct ConfigPublish {
    topic: String,
    path: PathBuf,
    start_at: Option<Duration>,
    period: Option<Duration>,
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

#[instrument(skip(process_stream))]
async fn capture_process_stream(
    process_stream: Result<impl Stream<Item = ProcessItem> + Send + std::marker::Unpin>,
) -> Result<String> {
    let mut output = String::new();
    let mut error = String::new();

    if let Ok(mut cmd_stream) = process_stream {
        while let Some(pi) = cmd_stream.next().await {
            match pi {
                ProcessItem::Exit(e) => {
                    debug!("Exit {e}");
                    /* TODO, how to know kill or error exit? */
                }
                ProcessItem::Error(e) => {
                    debug!("Error {e}");
                    error.push_str(&e);
                }
                ProcessItem::Output(o) => {
                    debug!("Output {o}");
                    output.push_str(&o);
                }
            }
        }
    } else {
        //error!("{:#?} not found", process);
        error.push_str(r#"Not Found}"#);
    }

    if error.len() == 0 {
        Ok(output)
    } else {
        Err(anyhow!(error))
    }
}

fn spawn_task_run_path_publish(
    chan_tx: mpsc::Sender<Command>,
    topic: String,
    path: PathBuf,
    timeout: Option<Duration>,
) -> Result<()> {
    let mut process = Process::new(&path);
    if let Ok(process_stream) = process.spawn_and_stream() {
        tokio::spawn(async move {
            let timeout = match timeout {
                Some(t) => t,
                None => Duration::from_secs(86400), /* XXX 24h */
            };
            tokio::select! {
                Ok(payload) = capture_process_stream(
                    //chan_tx.clone(),
                    //topic.to_string(),
                    Ok(process_stream)) => {
                    //debug!("task-{} completed", topic);

                    publish_message(chan_tx, topic, payload).await?;
                }
                _ = time::sleep(timeout) => {
                    error!("{} task timeout({:?}) exit", topic, timeout);
                    process.kill().await;
                }
                else => {
                }
            }
            /* help the rust type inferencer out, ref https://tokio.rs/tokio/tutorial/select */
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
    }

    Ok(())
}

#[instrument(
    //level = "info",
    name = "publish::task",
    skip(chan_tx, shared),
)]
async fn publish_task(chan_tx: mpsc::Sender<Command>, shared: Arc<Mutex<State>>) -> Result<()> {
    let mut entries: HashMap<String, (PathBuf, Option<Duration>, Option<Duration>)> =
        HashMap::new();
    if let Ok(state) = shared.lock() {
        if let Some(ps) = &state.cfg.publish {
            for p in ps {
                entries.insert(p.topic.clone(), (p.path.clone(), p.start_at, p.period));
            }
        }
    }

    //let mut expirations: BTreeMap<(Instant, u64), (String, Option<Duration>)> = BTreeMap::new();
    let mut expirations: ExpirationT = BTreeMap::new();
    let now = Instant::now();
    let mut id = 1;

    for (topic, (path, start_at, period)) in &entries {
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
                        timeout);
                }
            }
        }
    }

    let expirations_cloned = Arc::new(Mutex::new(expirations)).clone();
    tokio::spawn(async move {
        while let Some((when, topic)) = next_topics(expirations_cloned.clone()) {
            tokio::select! {
                _ = time::sleep_until(when) => {
                    if let Some((path, _, period)) =entries.get(&topic) {
                        _ = spawn_task_run_path_publish(
                            chan_tx.clone(),
                            topic.to_string(),
                            path.to_path_buf(),
                            *period);
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

    let future_sig_c = signal::ctrl_c();

    //tokio::join!();
    tokio::select! {
        _ = future_sig_c => {
            info!("exit by catch signal-c");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_toml_duration() {
    let cp = ConfigPublish {
        topic: String::from("test"),
        path: PathBuf::from("/tmp/test.sh"),
        start_at: Some(Duration::from_secs(1)),
        period: Some(Duration::from_secs(10)),
    };

    let toml = toml::to_string(&cp);
    assert_eq!(toml, Ok(String::from("hello")));
}
