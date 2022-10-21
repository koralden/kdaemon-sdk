use anyhow::Result;
use tokio::sync::{/*broadcast, Notify,*/ mpsc, oneshot};
use tracing::{debug, instrument};

pub mod aws_iot;
pub mod kap_daemon;
pub mod activate;
pub use self::activate::{activate, ActivateOpt};
pub mod misc;
pub use self::misc::{time_tools, TimeToolOpt};
#[cfg(feature = "boss-api")]
pub use self::misc::{boss_tools, CurlBossOpt};
#[cfg(feature = "ethers")]
pub use self::misc::{wallet_tools, WalletCommand};
pub mod daemon;
pub use self::daemon::{daemon, DaemonOpt};
pub mod publish_task;
pub mod subscribe_task;
pub mod kap_rule;

#[derive(Debug)]
#[allow(dead_code)]
pub enum DbCommand {
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
    Rpush {
        key: String,
        val: String,
        limit: usize,
    },
    /*AwsShadowPublish {
        key: String,
        val: String,
    },
    SubTaskNotify {
        topic: String,
        payload: String,
    },
    NotifySubscribe {
        key: String,
    },
    NotifySubscribeDone,*/
    Exit,
}

#[instrument(skip(chan_tx))]
pub async fn publish_message(
    chan_tx: &mpsc::Sender<DbCommand>,
    topic: String,
    payload: String,
) -> Result<()> {
    let (resp_tx, resp_rx) = oneshot::channel();

    chan_tx
        .send(DbCommand::Publish {
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
pub async fn set_message(
    chan_tx: mpsc::Sender<DbCommand>,
    topic: String,
    payload: String,
) -> Result<()> {
    let (resp_tx, resp_rx) = oneshot::channel();

    chan_tx
        .send(DbCommand::Set {
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
