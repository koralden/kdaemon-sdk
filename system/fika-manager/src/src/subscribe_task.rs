use anyhow::Result;
use tracing::{debug, error, warn};
use tokio::sync::mpsc;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::time::{self, Duration};
use process_stream::Process;

use crate::DbCommand;
use crate::publish_task::capture_process_stream;

#[derive(Debug)]
#[allow(dead_code)]
pub enum SubscribeCmd {
    Notify {
        topic: String,
        msg: String,
    },
    Exit,
}

pub async fn subscribe_ipc_post(
    subscribe_ipc_tx: mpsc::Sender<SubscribeCmd>,
    msg: Option<redis::Msg>,
    ) -> Result<()> {
    if let Some(msg) = msg {
        if let Ok(topic) = msg.get_channel::<String>() {
            let payload = msg.get_payload::<String>().unwrap_or("".into());
            subscribe_ipc_tx.send(SubscribeCmd::Notify {
                topic,
                msg: payload
            }).await?;
        } else {
            warn!("ipc/sub-task not channel? - {:?}?", msg);
        }
    } else {
        warn!("ipc/sub-task not msg!");
    }
    Ok(())
}

pub async fn subscribe_ipc_register(
    sub: &mut redis::aio::PubSub,
    sub_list: Option<Vec<String>>,
) -> Result<()> {
    if let Some(vs) = sub_list {
        for ss in vs {
            debug!("subscribe-task entry redis/subscribe {:?}", &ss);
            sub.subscribe(&ss).await?;
        }
    }

    Ok(())
}

pub async fn subscribe_main(
    mut subscribe_rx: mpsc::Receiver<SubscribeCmd>,
    _chan_tx: mpsc::Sender<DbCommand>,
    entries: HashMap<String, PathBuf>,
    ) -> Result<()> {
    loop {
        tokio::select! {
            Some(msg) = subscribe_rx.recv() => {
                match msg {
                    SubscribeCmd::Notify { topic, msg } => {
                        if let Some(path) = entries.get(&topic) {
                            debug!(
                                "got msg {:?} => {:?}/{:?} => path-{:?}",
                                msg, topic, msg, path
                                );
                            let mut cmd: Process = path.into();
                            cmd.arg(&msg);

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
                    },
                    SubscribeCmd::Exit => {
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}
