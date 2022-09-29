use anyhow::{anyhow, Result};
use tracing::{debug, error, info, instrument, warn};
use tokio::sync::mpsc;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use tokio::time::{self, Duration, Instant};
use process_stream::{Process, ProcessItem, Stream, StreamExt};
use std::sync::{Arc, Mutex};

use crate::{publish_message, set_message, DbCommand};

#[instrument(skip(process_stream))]
pub async fn capture_process_stream(
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

pub fn spawn_task_run_path_publish(
    chan_tx: mpsc::Sender<DbCommand>,
    topic: String,
    path: PathBuf,
    timeout: Option<Duration>,
    db_publish: Option<bool>,
    db_set: Option<bool>,
) -> Result<tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>> {
    info!(
        "spawn task run {:?} with topic {:?}/{:?}",
        &path, &topic, timeout
    );
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
                                    publish_message(&chan_tx, topic.clone(), payload.clone()).await?;
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
        }
        Err(e) => Err(anyhow!(e)),
    }
}

type ExpirationT = BTreeMap<(Instant, u64), (String, Option<Duration>, bool)>;

fn next_topics(expirations: Arc<Mutex<ExpirationT>>) -> Option<(Instant, String)> {
    let mut expirations = expirations.lock().unwrap();

    let expirations = &mut *expirations;
    let now = Instant::now();

    while let Some((&(when, id), (topic, _, _))) = expirations.iter().next() {
        if when >= now {
            let topic = topic.clone();
            expirations
                .entry((when, id))
                .and_modify(|curr| (*curr).2 = true);
            return Some((when, topic));
        } else {
            if let Some((topic, Some(period), scheduled)) = expirations.remove(&(when, id)) {
                /* same period time case, return it to force run */
                if when < now && scheduled == false {
                    expirations.insert((when, id), (topic.clone(), Some(period), true));
                    return Some((now, topic));
                } else {
                    let next = now + period;
                    expirations.insert((next, id), (topic, Some(period), false));
                }
            }
        }
    }
    None
}

pub async fn publish_main(
    chan_tx: mpsc::Sender<DbCommand>,
    entries: HashMap<String, (
            PathBuf,
            Option<Duration>,
            Option<Duration>,
            Option<bool>,
            Option<bool>,
        )>,
) -> Result<()> {
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
                expirations.insert((when, id), (topic.to_string(), *period, false));
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
                    expirations.insert((when, id), (topic.to_string(), Some(period), false));
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
