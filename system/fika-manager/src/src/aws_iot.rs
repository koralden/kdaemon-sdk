use anyhow::{anyhow, Result};
use futures_util::future;
use process_stream::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::fs;
use tokio::sync::{/*broadcast, Notify,*/ mpsc, oneshot};
use tokio::task;
use tracing::{debug, error, info, instrument, warn};
//use std::io;
use chrono::prelude::*;
use chrono::serde::ts_seconds;
use fika_manager::mqtt_client::{async_event_loop_listener, AWSIoTAsyncClient, AWSIoTSettings};
use fika_manager::{publish_message, DbCommand};
use rumqttc::{self, Packet, QoS};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
pub struct AwsIotProvisionConfig {
    pub ca: String,
    pub cert: String,
    pub key: String,
    pub template: String,
    pub thing_prefix: String,
    pub mac_address: String,
    pub serial_number: String,
    pub sku: String,
}

impl AwsIotProvisionConfig {
    pub fn generate_thing_name(&self, extra: Option<&str>) -> Option<String> {
        Some(format!(
            "{}_{}{}",
            &self.thing_prefix,
            &self.mac_address,
            extra.unwrap_or("")
        ))
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
pub struct AwsIotDedicatedConfig {
    pub ca: String,
    pub cert: String,
    pub key: String,
    pub thing_name: Option<String>,
    pub pull_topic: Option<Vec<String>>,
}

impl AwsIotDedicatedConfig {
    pub fn apply_thing_name(&mut self, name: Option<String>) -> Result<()> {
        if self.thing_name.is_none() {
            self.thing_name = name;
        } else {
            warn!("thing-name-{:?} have forced", self.thing_name.as_ref());
            //Err(anyhow!("thing-name have forced"))
        }
        Ok(())
    }

    pub async fn config_verify(&self) -> Result<()> {
        let file = fs::File::open(&self.cert).await?;
        let metadata = file.metadata().await?;
        if metadata.is_dir() || metadata.len() == 0 {
            return Err(anyhow!("{} invalid", &self.cert));
        }

        let file = fs::File::open(&self.key).await?;
        let metadata = file.metadata().await?;
        if metadata.is_dir() || metadata.len() == 0 {
            return Err(anyhow!("{} invalid", &self.key));
        }

        let file = fs::File::open(&self.ca).await?;
        let metadata = file.metadata().await?;
        if metadata.is_dir() || metadata.len() == 0 {
            return Err(anyhow!("{} invalid", &self.ca));
        }

        if self.thing_name.is_none() {
            return Err(anyhow!("{:?} invalid", self.thing_name));
        }

        Ok(())
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct AwsIotKeyCertificate {
    certificate_id: String,
    certificate_pem: String,
    private_key: String,
    certificate_ownership_token: String,
}

impl AwsIotKeyCertificate {
    pub async fn save(&self, dedicated: &AwsIotDedicatedConfig) -> Result<()> {
        fs::write(&dedicated.cert, &self.certificate_pem).await?;
        fs::write(&dedicated.key, &self.private_key).await?;
        Ok(())
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct AwsIotThingResponse {
    device_configuration: Value, /*
                                     FallbackUrl: String,
                                     LocationUrl: String
                                 },*/
    thing_name: String,
}

#[instrument(name = "mqtt::provision", skip(_db_chan))]
pub async fn mqtt_provision_task(
    endpoint: &str,
    provision: AwsIotProvisionConfig,
    dedicated: Option<AwsIotDedicatedConfig>,
    _db_chan: mpsc::Sender<DbCommand>,
) -> Result<AwsIotDedicatedConfig> {
    let client_id = format!("provisioner_{}", provision.serial_number);
    let aws = AWSIoTSettings::new(
        client_id,
        provision.ca.clone(),
        provision.cert,
        provision.key,
        endpoint.to_string(),
        None,
    );

    let mut dedicated = if let Some(d) = dedicated {
        d
    } else {
        AwsIotDedicatedConfig {
            ca: provision.ca.clone(),
            cert: "/userdata/generated.cert.pem".to_string(),
            key: "/userdata/generated.key.pem".to_string(),
            thing_name: None,
            pull_topic: None,
        }
    };

    if let Ok((iot_core_client, eventloop_stuff)) = AWSIoTAsyncClient::new(aws).await {
        iot_core_client
            .subscribe(
                "$aws/certificates/create/json/accepted".to_string(),
                QoS::AtLeastOnce,
            )
            .await
            .unwrap();
        let mut receiver = iot_core_client.get_receiver().await;

        let recv_thread: task::JoinHandle<Result<AwsIotDedicatedConfig>> = tokio::spawn(
            async move {
                loop {
                    match receiver.recv().await {
                        Ok(event) => {
                            match event {
                            Packet::Publish(p) => {
                                match p.topic.as_str() {
                                    "$aws/certificates/create/json/accepted" => {
                                        match serde_json::from_slice::<AwsIotKeyCertificate>(&p.payload) {
                                            Ok(g) => {
                                                //debug!("got key&certificate from AWS-IOT/provision - {:?}", g);
                                                let _ = g.save(&dedicated).await;
                                                let payload = json!({
                                                    "certificateOwnershipToken": g.certificate_ownership_token,
                                                    "parameters": {
                                                        "SerialNumber": provision.serial_number,
                                                        "MAC": provision.mac_address,
                                                        "DeviceLocation": provision.sku,
                                                    }
                                                }).to_string();
                                                let topic = format!("$aws/provisioning-templates/{}/provision/json", provision.template);
                                                iot_core_client.publish(topic, QoS::AtLeastOnce, payload).await.unwrap();
                                            },
                                            Err(e) => {
                                                error!("serde/json fail {:?}", e);
                                            }
                                        }
                                    },
                                    _ => {
                                        let topic = format!("$aws/provisioning-templates/{}/provision/json/accepted", provision.template);
                                        if topic == p.topic {
                                            let r = iot_core_client.get_client()
                                                .await
                                                .disconnect()
                                                .await;
                                            debug!("mqtt provision client disconnect - {:?}", r);

                                            match serde_json::from_slice::<AwsIotThingResponse>(&p.payload) {
                                                Ok(t) => {
                                                    debug!("topic-{} got {:?}", topic, t);
                                                    dedicated.thing_name = Some(t.thing_name);

                                                    info!("return from recv thread - {:?}", &dedicated);
                                                    return Ok(dedicated);
                                                },
                                                Err(e) => {
                                                    error!("serde/json[topic - {}] fail {:?}", topic, e);
                                                    return Err(anyhow!("RegisterThing response invalid"));
                                                }
                                            }
                                        } else {
                                            println!("Received message {:?} on topic: {}", p.payload, p.topic);
                                        }
                                    },
                                }
                            },
                            Packet::SubAck(s) => {
                                match s.pkid {
                                    1 => iot_core_client.subscribe("$aws/certificates/create/json/rejected".to_string(), QoS::AtLeastOnce).await.unwrap(),
                                    2 => iot_core_client.subscribe(format!("$aws/provisioning-templates/{}/provision/json/accepted", &provision.template), QoS::AtLeastOnce).await.unwrap(),
                                    3 => iot_core_client.subscribe(format!("$aws/provisioning-templates/{}/provision/json/rejected", &provision.template), QoS::AtLeastOnce).await.unwrap(),
                                    _ => {
                                        debug!("final subscribe response {:?}", s);
                                        iot_core_client.publish("$aws/certificates/create/json".to_string(),
                                        QoS::AtLeastOnce, "").await.unwrap();
                                    },
                                }
                            },
                            _ => debug!("Got event on receiver: {:?}", event),
                        }
                        }
                        Err(_) => (),
                    }
                }
            },
        );
        let listen_thread: task::JoinHandle<Result<()>> = tokio::spawn(async move {
            let r = async_event_loop_listener(eventloop_stuff).await;
            if r.is_err() {
                error!("listen thread error - {:?}", r);
            }
            Ok(())
        });

        match tokio::join!(recv_thread, listen_thread) {
            (Ok(dedicated), Ok(_)) => {
                info!("provision listen/recv thread normal terminated");
                Ok(dedicated.unwrap())
            }
            (Err(e), Ok(_)) => {
                error!("provision recv thread abnormal terminated - {:?}", e);
                Err(anyhow!(e))
            }
            (Ok(dedicated), Err(e)) => {
                error!("provision listen thread abnormal terminated - {:?}", e);
                Ok(dedicated.unwrap())
            }
            (Err(e1), Err(e2)) => {
                info!(
                    "provision listen/recv thread abnormal terminated - {:?}/{:?}",
                    e1, e2
                );
                Err(anyhow!(e1))
            }
        }
    } else {
        Err(anyhow!("TODO"))
    }
}

#[instrument(name = "mqtt::dedicated")]
pub async fn mqtt_dedicated_create(
    endpoint: &str,
    dedicated: &AwsIotDedicatedConfig,
) -> Result<(
    AWSIoTAsyncClient,
    (
        rumqttc::EventLoop,
        tokio::sync::broadcast::Sender<rumqttc::Packet>,
    ),
)> {
    dedicated.config_verify().await?;

    let thing_name = dedicated.thing_name.as_ref().unwrap();
    let client_id = thing_name.clone();
    let aws = AWSIoTSettings::new(
        client_id,
        dedicated.ca.clone(),
        dedicated.cert.clone(),
        dedicated.key.clone(),
        endpoint.to_string(),
        None,
    );

    AWSIoTAsyncClient::new(aws)
        .await
        .or_else(|e| Err(anyhow!("mqtt connect fail - {e}")))
}

#[instrument(name = "mqtt::dedicated", skip(sub_conn, db_chan, iot))]
pub async fn mqtt_dedicated_start(
    mut sub_conn: redis::aio::PubSub,
    db_chan: mpsc::Sender<DbCommand>,
    thing_name: String,
    iot: (
        AWSIoTAsyncClient,
        (
            rumqttc::EventLoop,
            tokio::sync::broadcast::Sender<rumqttc::Packet>,
        ),
    ),
    pull_topic: Option<Vec<String>>,
) -> Result<()> {
    let (iot_core_client, eventloop_stuff) = iot;
    /* topic - '#' to monitor all event */
    let topic = format!("$aws/things/{}/shadow/#", thing_name);
    iot_core_client.subscribe(&topic, QoS::AtMostOnce).await?;
    info!("aws/iot subscribed {} ok", &topic);
    let topic = format!("$aws/things/{}/jobs/#", thing_name);
    iot_core_client.subscribe(&topic, QoS::AtMostOnce).await?;
    info!("aws/iot subscribed {} ok", &topic);

    sub_conn.psubscribe("kap/aws/raw/*").await?;
    info!("ipc/db psubscribed kap/aws/raw/* ok");
    sub_conn.psubscribe("kap/aws/shadow/*").await?;
    info!("ipc/db psubscribed kap/aws/shadow/* ok");

    sub_conn.psubscribe("kap/cmp/publish/jobs/update/*").await?;
    info!("ipc/db psubscribed kap/cmp/publish/jobs/update/* ok");

    if let Some(pull_topic) = pull_topic {
        let _: Vec<Result<(), rumqttc::ClientError>> =
            future::join_all(pull_topic.iter().map(|t| async {
                let t = format!("$aws/things/{}/shadow/{}/get", &thing_name, t.as_str());
                iot_core_client.publish(t, QoS::AtMostOnce, "").await
            }))
            .await;
    }

    let recv1_thread = tokio::spawn(async move {
        let mut receiver = iot_core_client.get_receiver().await;
        let mut sub_stream = sub_conn.on_message();
        loop {
            tokio::select! {
                msg = receiver.recv() => {
                    _ = mqtt_dedicated_handle_iot(&iot_core_client, &db_chan, msg).await;
                },
                msg = sub_stream.next() => {
                    _ = mqtt_dedicated_handle_ipc(&iot_core_client, &db_chan, &thing_name, msg).await;
                },
            }
        }
    });
    let listen_thread: task::JoinHandle<Result<()>> = tokio::spawn(async move {
        let r = async_event_loop_listener(eventloop_stuff).await;
        if r.is_err() {
            error!("dedicated thread error - {:?}", r);
        }
        Ok(())
    });
    _ = tokio::join!(recv1_thread, listen_thread);
    Ok(())
}

#[instrument(name = "mqtt::dedicated", skip(sub_conn, db_chan))]
pub async fn mqtt_dedicated_create_start(
    endpoint: &str,
    dedicated: &AwsIotDedicatedConfig,
    sub_conn: redis::aio::PubSub,
    db_chan: mpsc::Sender<DbCommand>,
) -> Result<()> {
    if let Some(t) = dedicated.thing_name.as_ref() {
        let thing_name = t.clone();
        let pull_topic = dedicated.pull_topic.clone();

        if let Ok(iot) = mqtt_dedicated_create(endpoint, dedicated).await {
            mqtt_dedicated_start(sub_conn, db_chan, thing_name, iot, pull_topic).await
        } else {
            Err(anyhow!("mqtt dedicated create fail"))
        }
    } else {
        return Err(anyhow!("mqtt dedicated create fail"));
    }
}

async fn mqtt_dedicated_handle_iot(
    _iot: &AWSIoTAsyncClient,
    db_chan: &mpsc::Sender<DbCommand>,
    msg: Result<Packet, tokio::sync::broadcast::error::RecvError>,
) -> Result<()> {
    match msg {
        Ok(event) => match event {
            Packet::Publish(p) => {
                info!("[aws][kap] receive {:?} ", &p);
                if p.payload.len() == 0 {
                    return Ok(());
                }
                debug!("[aws][kap] real payload[{:?}]", &p.payload);

                let topic = p.topic;

                if topic.find("/get/rejected").is_some() {
                    warn!("[aws][kap] {} topic non-exist!", &topic);
                    return Err(anyhow!("{} topic non-exist", &topic));
                } else if topic.find("/update/rejected").is_some() {
                    error!("[aws][kap] {} content invalid!", &topic);
                    return Err(anyhow!("{} content invalid!", &topic));
                } else if topic.find("/delete/rejected").is_some() {
                    error!("[aws][kap] {} action invalid!", &topic);
                    return Err(anyhow!("{} action invalid!", &topic));
                }

                if topic
                    .find("/get/accepted")
                    .or_else(|| topic.find("/update/accepted"))
                    .is_none()
                {
                    warn!("omit due not get/accepted & update/accepted");
                    return Ok(());
                }

                let payload = std::str::from_utf8(&p.payload)?.to_string();

                post_iot_publish_msg(db_chan, topic, payload).await?;
            }
            _ => debug!("[aws][kap] other event[{:?}]", event),
        },
        Err(_) => (),
    }
    Ok(())
}

enum TopicType<'a, 'b> {
    Raw { topic: &'a str, thing: &'b str },
    ShadowUpdate { topic: &'a str, thing: &'b str },
    JobsUpdate { thing: &'b str },
}

impl TopicType<'_, '_> {
    fn to_string<'a, 'b>(self) -> String {
        match self {
            Self::Raw { topic, thing } => {
                format!("$aws/things/{}/{}", thing, topic)
            }
            Self::JobsUpdate { thing } => {
                format!("$aws/things/{}/jobs/update", thing)
            }
            TopicType::ShadowUpdate { topic, thing } => {
                /* name/{SHADOW} for names shadow
                 * {SHADOW} for classic shadow */
                format!("$aws/things/{}/shadow/{}/update", thing, topic)
            }
        }
    }
}

fn post_ipc_msg<'a>(msg: &'a redis::Msg, thing: &str) -> Result<(String, String)> {
    let payload: String = msg.get_payload()?;
    if let Ok(pattern) = msg.get_pattern::<String>() {
        let topic: String;
        let ofs: usize = pattern.len() - 1;

        let payload = if pattern.find("kap/aws/shadow").is_some() {
            topic = TopicType::ShadowUpdate {
                topic: &msg.get_channel_name()[ofs..],
                thing,
            }
            .to_string();

            let reported = serde_json::from_str::<serde_json::Value>(&payload[..])?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?;
            let client_token = format!("{}.{}", timestamp.as_secs(), timestamp.subsec_millis());

            debug!(
                "ipc timestamp[{}] payload[{:?}] to {:?}",
                client_token, &payload, reported
            );

            json!({
                "state": {
                    "reported": reported
                },
                "clientToken": client_token
            })
            .to_string()
        } else if pattern.find("kap/aws/jobs").is_some() {
            /* TODO */
            warn!("ipc jobs/update not implement");
            topic = TopicType::JobsUpdate { thing }.to_string();
            payload
        } else {
            /* pure raw */
            topic = TopicType::Raw {
                topic: &msg.get_channel_name()[ofs..],
                thing,
            }
            .to_string();
            payload
        };

        Ok((topic, payload))
    } else {
        /* not psubscribe? */
        let topic = msg.get_channel_name().to_string();
        Ok((topic, payload))
    }
}

async fn mqtt_dedicated_handle_ipc(
    iot: &AWSIoTAsyncClient,
    _db_chan: &mpsc::Sender<DbCommand>,
    thing: &str,
    msg: Option<redis::Msg>,
) -> Result<()> {
    debug!("ipc get msg - {:?}", msg);

    match msg {
        Some(m) => {
            let (topic, payload) = post_ipc_msg(&m, thing)?;

            match iot.publish(&topic, QoS::AtMostOnce, payload).await {
                Ok(_) => {
                    info!("[kap][aws] send {:?} to", &topic);
                    /*let now = Instant::now();
                    db_chan
                        .send(DbCommand::Rpush {
                            key: format!("history/to/{}", &topic),
                            val: format!("{:?}", now),
                            limit: 100,
                        })
                        .await?;*/
                }
                Err(e) => {
                    error!("[kap][aws] send/publish fail - {:?}", e);
                    return Err(anyhow!("iot publish fail - {:?}", e));
                }
            }
        }
        None => {
            warn!("ipc other message??");
        }
    }

    Ok(())
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct AwsIotShadowAcceptState {
    desired: Option<serde_json::Value>,
    reported: Option<serde_json::Value>,
    delta: Option<serde_json::Value>,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct AwsIotShadowAcceptMetadata {
    desired: Option<serde_json::Value>,
    reported: Option<serde_json::Value>,
    delta: Option<serde_json::Value>,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct AwsIotShadowAccept {
    state: AwsIotShadowAcceptState,
    metadata: AwsIotShadowAcceptMetadata,
    version: u16,
    #[serde(with = "ts_seconds")]
    timestamp: DateTime<Utc>,
}

async fn shadow_version_compare(
    db_chan: &mpsc::Sender<DbCommand>,
    topic: &str,
    version: u16,
) -> Result<()> {
    let (db_req, db_resp) = oneshot::channel();
    db_chan
        .send(DbCommand::Get {
            key: topic.to_string(),
            resp: db_req,
        })
        .await?;

    let orig = db_resp.await;

    if let Ok(Some(o)) = orig {
        debug!("[db] origin {:?}", o);
        if let Ok(o) = serde_json::from_str::<AwsIotShadowAccept>(o.as_str()) {
            if o.version >= version {
                info!(
                    "[db] shadow content not changed ({} vs {})",
                    o.version, version
                );
                return Err(anyhow!("not need upgrade"));
            }
        }
    }
    return Ok(());
}

async fn post_iot_publish_msg(
    db_chan: &mpsc::Sender<DbCommand>,
    topic: String,
    payload: String,
) -> Result<()> {
    let shadow: AwsIotShadowAccept = serde_json::from_str(payload.as_str())?;
    debug!("payload string conver => {:?}", shadow);
    let sub_topic: String = topic
        .split('/')
        .skip(3)
        .take(3)
        .fold(String::from("aws/kap"), |sum, i| sum + "/" + i);
    if shadow.state.desired.is_some() {
        shadow_version_compare(db_chan, &sub_topic, shadow.version).await?;

        let p = serde_json::to_string(&shadow.state.desired.unwrap())?;
        let t = format!("{}/{}", &sub_topic, "state");
        publish_message(db_chan, t, p).await?;
    }

    let (resp_tx, resp_rx) = oneshot::channel();
    db_chan
        .send(DbCommand::Set {
            key: sub_topic,
            val: payload.clone(),
            resp: resp_tx,
        })
        .await?;

    match resp_rx.await {
        Ok(_) => {
            /*let now = Instant::now();
            db_chan
                .send(DbCommand::Rpush {
                    key: format!("history/from/{}", topic),
                    val: format!("{:?}", now),
                    limit: 100,
                })
            .await?;*/
        }
        Err(e) => {
            return Err(anyhow!("ipc/send {:?}/{:?} fail - {:?}", topic, payload, e));
        }
    }
    Ok(())
}
