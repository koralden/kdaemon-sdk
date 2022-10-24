use anyhow::{anyhow, Result};
use async_trait::async_trait;
use clap::Args;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::process::Command;
use tokio::signal;
use tracing::{debug, error, instrument, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::aws_iot::{mqtt_provision_task, AwsIotKeyCertificate};
use crate::kap_daemon::{KBossConfig, KNetworkConfig, KPorConfig};
use crate::kap_daemon::{KCmpConfig, KCoreConfig, KdaemonConfig};
use crate::kap_rule::RuleConfig;
use atty::Stream;
use chrono::prelude::*;
use colored_json::to_colored_json_auto;

//type DbConnection = redis::aio::Connection;

#[derive(Args, Debug, Clone)]
#[clap(about = "FIKA manager activate with factory data")]
pub struct ActivateOpt {
    #[clap(
        short = 'p',
        long = "activate-rule",
        default_value = "/etc/fika_manager/activate.toml"
    )]
    active: String,
    #[clap(short = 'l', long = "log-level", default_value = "info")]
    log_level: String,
    #[clap(short, long, action)]
    force: bool,
    #[clap(short = 'c', long = "config", default_value = "/userdata/kdaemon.toml")]
    config: String,
    #[clap(
        short = 'r',
        long = "rule",
        default_value = "/etc/fika_manager/rule.toml"
    )]
    rule: String,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct KapFactory {
    core: KapCoreConfig,
    network: KapNetworkConfig,
    por: KapPorConfig,
    boss: KapBossConfig,
    cmp: KapCmpConfig,
}

#[async_trait]
trait FactoryAction {
    async fn post(&self) -> Result<()> {
        if let Some(post) = self.get_post() {
            let mut child = if let Some(key) = self.get_key() {
                if let Some(cfg) = self.get_cfg() {
                    let args = serde_json::to_string(&cfg)?;
                    Command::new(&post)
                        .arg(&args)
                        .arg(key)
                        .spawn()
                        .map_err(|e| anyhow!("{post}/{args}/{key} run fail - {e}"))?
                } else {
                    Command::new(&post)
                        .arg(key)
                        .spawn()
                        .map_err(|e| anyhow!("{post}/{key} run fail - {e}"))?
                }
            } else {
                if let Some(cfg) = self.get_cfg() {
                    let args = serde_json::to_string(&cfg)?;
                    Command::new(&post)
                        .arg(&args)
                        .spawn()
                        .map_err(|e| anyhow!("{post}/{args} run fail - {e}"))?
                } else {
                    Command::new(&post)
                        .spawn()
                        .map_err(|e| anyhow!("{post} run fail - {e}"))?
                }
            };

            let status = child.wait().await?;
            debug!("command {} run completed - {}", post, status);
        }

        Ok(())
    }
    async fn pre(&self) -> Result<()> {
        if let Some(pre) = self.get_pre() {
            let mut child = if let Some(key) = self.get_key() {
                if let Some(cfg) = self.get_cfg() {
                    let args = serde_json::to_string(&cfg)?;
                    Command::new(&pre)
                        .arg(&args)
                        .arg(key)
                        .spawn()
                        .map_err(|e| anyhow!("{pre}/{args}/{key} run fail - {e}"))?
                } else {
                    Command::new(&pre)
                        .arg(key)
                        .spawn()
                        .map_err(|e| anyhow!("{pre}/{key} run fail - {e}"))?
                }
            } else {
                if let Some(cfg) = self.get_cfg() {
                    let args = serde_json::to_string(&cfg)?;
                    Command::new(&pre)
                        .arg(&args)
                        .spawn()
                        .map_err(|e| anyhow!("{pre}/{args} run fail - {e}"))?
                } else {
                    Command::new(&pre)
                        .spawn()
                        .map_err(|e| anyhow!("{pre} run fail - {e}"))?
                }
            };

            let status = child.wait().await?;
            debug!("command {} run completed - {}", pre, status);
        }

        Ok(())
    }

    async fn key_apply(&self) -> Result<()> {
        let mut db_conn = redis::Client::open("redis://127.0.0.1:6379")
            .map_err(|e| anyhow!("db/redis open fail - {e}"))?
            .get_async_connection()
            .await
            .map_err(|e| anyhow!("db/redis async connect fail - {e}"))?;

        if let Some(key) = self.get_key() {
            if let Some(args) = self.get_cfg() {
                //serde_json::to_string(&self.cfg)?;
                debug!("args as {}", args);
                db_conn
                    .set(&key, &args)
                    .await
                    .map_err(|e| anyhow!("db/redis set {key}/{args} fail - {e}"))?;

                let key = format!("{}.done", key);
                db_conn.incr(&key, 1).await?
            }
        }

        Ok(())
    }
    fn get_key(&self) -> Option<&String>;
    fn get_post(&self) -> Option<&String>;
    fn get_pre(&self) -> Option<&String>;
    fn get_cfg(&self) -> Option<String>;

    async fn run(&self, _force: bool) -> Result<()> {
        _ = self.pre().await?;
        _ = self.key_apply().await;
        _ = self.post().await?;

        Ok(())
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct KapCoreConfig {
    cfg: Option<KCoreConfig>,
    key: Option<String>,
    post: Option<String>,
    pre: Option<String>,
}

#[async_trait]
impl FactoryAction for KapCoreConfig {
    fn get_key(&self) -> Option<&String> {
        self.key.as_ref()
    }

    fn get_post(&self) -> Option<&String> {
        self.post.as_ref()
    }

    fn get_pre(&self) -> Option<&String> {
        self.pre.as_ref()
    }

    fn get_cfg(&self) -> Option<String> {
        None
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct KapNetworkConfig {
    cfg: Option<KNetworkConfig>,
    key: Option<String>,
    post: Option<String>,
    pre: Option<String>,
}

#[async_trait]
impl FactoryAction for KapNetworkConfig {
    fn get_key(&self) -> Option<&String> {
        self.key.as_ref()
    }

    fn get_post(&self) -> Option<&String> {
        self.post.as_ref()
    }

    fn get_pre(&self) -> Option<&String> {
        self.pre.as_ref()
    }

    fn get_cfg(&self) -> Option<String> {
        None
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct KapPorConfig {
    cfg: Option<KPorConfig>,
    key: Option<String>,
    post: Option<String>,
    pre: Option<String>,
}

#[async_trait]
impl FactoryAction for KapPorConfig {
    fn get_key(&self) -> Option<&String> {
        self.key.as_ref()
    }

    fn get_post(&self) -> Option<&String> {
        self.post.as_ref()
    }

    fn get_pre(&self) -> Option<&String> {
        self.pre.as_ref()
    }

    fn get_cfg(&self) -> Option<String> {
        None
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct KapBossConfig {
    cfg: Option<KBossConfig>,
    key: Option<String>,
    post: Option<String>,
    pre: Option<String>,
}

#[async_trait]
impl FactoryAction for KapBossConfig {
    fn get_key(&self) -> Option<&String> {
        self.key.as_ref()
    }

    fn get_post(&self) -> Option<&String> {
        self.post.as_ref()
    }

    fn get_pre(&self) -> Option<&String> {
        self.pre.as_ref()
    }

    fn get_cfg(&self) -> Option<String> {
        None
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct KapCmpConfig {
    cfg: Option<KCmpConfig>,
    key: Option<String>,
    post: Option<String>,
    pre: Option<String>,
}

#[async_trait]
impl FactoryAction for KapCmpConfig {
    fn get_key(&self) -> Option<&String> {
        self.key.as_ref()
    }

    fn get_post(&self) -> Option<&String> {
        self.post.as_ref()
    }

    fn get_pre(&self) -> Option<&String> {
        self.pre.as_ref()
    }

    fn get_cfg(&self) -> Option<String> {
        None
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ActivateCertificate {
    name: String, /* as thing-name */
    id: String,   /* wallet-address */
    certificate: String,
    issue_time: DateTime<Utc>,
}

#[instrument(name = "fleet-provision")]
async fn iot_fleet_provision(
    rule_path: &str,
    config_path: &str,
    force: bool,
) -> Result<ActivateCertificate> {
    let rule: RuleConfig = RuleConfig::build_from(rule_path)
        .await
        .map_err(|e| anyhow!("rule-{rule_path} build-from fail - {e}"))?;
    let cfg: KdaemonConfig = KdaemonConfig::build_from(config_path)
        .await
        .map_err(|e| anyhow!("config-{config_path} build-from fail - {e}"))?;

    let cert = if cfg.cmp.config_verify().await.is_ok() && force == false {
        debug!("MQTT provision use original one");
        AwsIotKeyCertificate::reload(&cfg.cmp.cert).await?
    } else {
        let provision_rule = if let Some(aws) = rule.aws {
            if aws.provision.is_none() {
                error!("rule/aws/provision section invalid");
                return Err(anyhow!("rule/aws/provision section invalid"));
            }
            aws.provision.unwrap()
        } else {
            error!("rule/aws section invalid");
            return Err(anyhow!("rule/aws section invalid"));
        };

        mqtt_provision_task(&cfg, &provision_rule).await?
    };

    Ok(ActivateCertificate {
        name: cfg.cmp.thing,
        id: cfg.core.wallet_address,
        certificate: cert.0,
        issue_time: cert.1,
    })
}

//#[instrument(name = "activate", skip(opt))]
async fn main_task(opt: ActivateOpt) -> Result<()> {
    let cfg = fs::read_to_string(&opt.active)
        .await
        .map_err(|e| anyhow!("{} open/read fail - {}", &opt.active, e))?;
    let cfg: KapFactory =
        toml::from_str(&cfg).map_err(|e| anyhow!("{} invalid toml format - {}", &opt.active, e))?;
    let force = opt.force;

    debug!("active-rule content as {:#?}", cfg);

    _ = cfg.core.run(force).await?;
    _ = cfg.network.run(force).await?;
    _ = cfg.por.run(force).await?;
    _ = cfg.boss.run(force).await?;
    _ = cfg.cmp.run(force).await?;

    let cert = iot_fleet_provision(&opt.rule, &opt.config, force).await?;
    let feedback = serde_json::to_string(&cert)?;

    if atty::is(Stream::Stdout) {
        println!(
            "################################# [Activation code] #################################"
        );
        let color = to_colored_json_auto(&serde_json::from_str::<serde_json::Value>(&feedback)?)?;
        println!("{}", color);
        println!(
            "#####################################################################################"
        );
    } else {
        println!("{feedback}");
    }

    Ok(())
}

//pub type MyError = Box<dyn std::error::Error + Send + Sync>;
fn set_up_logging(log_level: &str) -> Result<()> {
    // See https://docs.rs/tracing for more info
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

//#[tokio::main]
pub async fn activate(opt: ActivateOpt) -> Result<()> {
    set_up_logging(&opt.log_level)?;
    debug!("activate-rule path as {}", opt.active);

    let main_jhandle = tokio::spawn(main_task(opt));
    let future_sig_c = signal::ctrl_c();

    tokio::select! {
        r = main_jhandle => {
            let r = r?;
            debug!("main-task exit due to {:?}", r);
            r
        },
        _ = future_sig_c => {
            warn!("exit by catch signal-c");
            Ok(())
        },
    }
}

/*#[tokio::test]
async fn test_toml_duration() {
    let cp = ConfigTask {
        topic: String::from("test"),
        path: PathBuf::from("/tmp/test.sh"),
        start_at: Some(Duration::from_secs(1)),
        period: Some(Duration::from_secs(10)),
    };

    let toml = toml::to_string(&cp);
    assert_eq!(toml, Ok(String::from("hello")));
}*/
