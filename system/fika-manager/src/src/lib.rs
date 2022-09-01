use anyhow::Result;
use tokio::sync::{/*broadcast, Notify,*/ mpsc, oneshot};
use tracing::{debug, instrument};

pub mod kap_ez;
pub use kap_ez::NetworkMenu;
pub use kap_ez::PorMenu;

pub mod kap_boss;
pub use kap_boss::BossMenu;

pub mod kap_cmp;
pub use kap_cmp::CmpMenu;

pub mod kap_core;
pub use kap_core::CoreMenu;

pub mod mqtt_client;
pub use self::mqtt_client::{async_event_loop_listener, AWSIoTAsyncClient, AWSIoTSettings};
pub use rumqttc::{EventLoop, Packet, Publish, QoS};
pub mod mqtt_error;
pub use self::mqtt_error::AWSIoTError;

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
