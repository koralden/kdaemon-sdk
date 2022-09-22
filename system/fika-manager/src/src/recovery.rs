use anyhow::Result;
use clap::Args;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::process::Command;
use tokio::signal;
use tracing::{debug, info, instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use async_trait::async_trait;

use crate::kap_daemon::{KCoreConfig, KNetworkConfig, KPorConfig, KBossConfig, KCmpConfig};

type DbConnection = redis::aio::Connection;

#[derive(Args, Debug, Clone)]
#[clap(
    about = "FIKA manager recovery with factory data"
)]
pub struct RecoveryOpt {
    #[clap(
        short = 'c',
        long = "config",
        default_value = "/etc/fika_manager/recovery.toml"
    )]
    config: String,
    #[clap(short = 'l', long = "log-level", default_value = "info")]
    log_level: String,
    #[clap(short, long, action)]
    force: bool,
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
                    //debug!("args as {}", args);
                    Command::new(&post).arg(&args).arg(key).spawn()?
                } else {
                    Command::new(&post).arg(key).spawn()?
                }
            } else {
                if let Some(cfg) = self.get_cfg() {
                    let args = serde_json::to_string(&cfg)?;
                    //debug!("args as {}", args);
                    Command::new(&post).arg(&args).spawn()?
                } else {
                    Command::new(&post).spawn()?
                }
            };

            let status = child.wait().await?;
            info!("command {} run completed - {}", post, status);
        }

        Ok(())
    }
    async fn pre(&self) -> Result<()> {
        if let Some(pre) = self.get_pre() {
            let mut child = if let Some(key) = self.get_key() {
                if let Some(cfg) = self.get_cfg() {
                    let args = serde_json::to_string(&cfg)?;
                    //debug!("args as {}", args);
                    Command::new(&pre).arg(&args).arg(key).spawn()?
                } else {
                    Command::new(&pre).arg(key).spawn()?
                }
            } else {
                if let Some(cfg) = self.get_cfg() {
                    let args = serde_json::to_string(&cfg)?;
                    //debug!("args as {}", args);
                    Command::new(&pre).arg(&args).spawn()?
                } else {
                    Command::new(&pre).spawn()?
                }
            };

            let status = child.wait().await?;
            info!("command {} run completed - {}", pre, status);
        }

        Ok(())
    }

    async fn key_apply(&self, db_conn: &mut DbConnection) -> Result<()> {
        if let Some(key) = self.get_key() {
            if let Some(args) = self.get_cfg() { //serde_json::to_string(&self.cfg)?;
                debug!("args as {}", args);
                db_conn.set(&key, &args).await?;
            }
        }

        Ok(())
    }
    fn get_key(&self) -> Option<&String>;
    fn get_post(&self) -> Option<&String>;
    fn get_pre(&self) -> Option<&String>;
    fn get_cfg(&self) -> Option<String>;

    async fn run(&self, db_conn: &mut DbConnection, force: bool) -> Result<()> {
        let key = if let Some(key) = self.get_key() {
            let key = format!("{}.done", key);
            if force == false && db_conn.exists::<&str, bool>(&key).await? == true {
                debug!("db key - {} exist without force", &key);
                return Ok(());
            }
            Some(key)
        } else {
            None
        };

        _ = self.pre().await?;
        _ = self.key_apply(db_conn).await?;
        _ = self.post().await?;

        if let Some(key) = key {
            db_conn.incr(&key, 1).await?;
            debug!("{} run done", &key);
        }

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

#[instrument(name = "recovery", skip(cfg))]
async fn main_task(cfg: KapFactory, force: bool) -> Result<()> {
    debug!("cfg content as {:#?}", cfg);

    let mut db_conn = redis::Client::open("redis://127.0.0.1:6379")?
        .get_async_connection()
        .await?;
    //let db_conn = Arc::new(Mutex::new(db_conn));

    _ = cfg.core.run(&mut db_conn, force).await?;
    _ = cfg.network.run(&mut db_conn, force).await?;
    _ = cfg.por.run(&mut db_conn, force).await?;
    _ = cfg.boss.run(&mut db_conn, force).await?;
    _ = cfg.cmp.run(&mut db_conn, force).await?;

    db_conn.incr("kap.recovery.done", 1).await?;

    Ok(())
}

pub type MyError = Box<dyn std::error::Error + Send + Sync>;
fn set_up_logging(log_level: &str) -> Result<(), MyError> {
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
pub async fn recovery(opt: RecoveryOpt) -> Result<(), MyError> {
    //let opt = Opt::parse();
    set_up_logging(&opt.log_level)?;
    debug!("config as {}", opt.config);

    let cfg = fs::read_to_string(opt.config).await?;
    let cfg: KapFactory = toml::from_str(&cfg)?;
    let force = opt.force;

    let main_jhandle = tokio::spawn(main_task(cfg, force));
    let future_sig_c = signal::ctrl_c();

    tokio::select! {
        r = main_jhandle => {
            info!("main-task exit due to {:?}", r);
        },
        _ = future_sig_c => {
            info!("exit by catch signal-c");
        },
    }

    Ok(())
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
