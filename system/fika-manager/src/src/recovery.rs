use anyhow::Result;
use clap::Parser;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
//use std::sync::{Arc, Mutex};
use tokio::fs;
use tokio::process::Command;
use tokio::signal;
//use tokio::sync::{/*broadcast, Notify,*/ mpsc, oneshot};
//use tokio::time::{self, Duration, Instant};
use tracing::{debug, info, instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
//use bytes::Bytes;
//use std::iter::repeat_with;
//use futures_util::stream::stream::StreamExt;
//use futures_util::StreamExt as _;
//use std::io;
//use std::path::PathBuf;
use async_trait::async_trait;

use fika_manager::kap_boss::BossMenu;
use fika_manager::kap_cmp::CmpMenu;
use fika_manager::kap_core::CoreMenu;
use fika_manager::kap_ez::{NetworkMenu, PorMenu};

//type DbConnection = Arc<Mutex<redis::aio::Connection>>;
type DbConnection = redis::aio::Connection;

#[derive(Parser, Debug, Clone)]
#[clap(
    name = "fika-manager-recovery",
    about = "FIKA manager recovery with factory data"
)]
struct Opt {
    #[clap(
        short = 'c',
        long = "config",
        default_value = "/etc/fika_manager/factory.toml"
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
    async fn post(&self) -> Result<()>;
    async fn pre(&self) -> Result<()>;
    async fn key_apply(&self, db_conn: &mut DbConnection, force: bool) -> Result<()>;

    async fn run(&self, db_conn: &mut DbConnection, force: bool) -> Result<()> {
        _ = self.pre().await?;
        _ = self.key_apply(db_conn, force).await?;
        _ = self.post().await?;
        Ok(())
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct KapCoreConfig {
    cfg: CoreMenu,
    key: String,
    post: String,
    pre: Option<String>,
}

#[async_trait]
impl FactoryAction for KapCoreConfig {
    #[instrument(name = "core-post", skip(self))]
    async fn post(&self) -> Result<()> {
        let post = &self.post;
        let args = serde_json::to_string(&self.cfg)?;
        //debug!("args as {}", args);

        let key = &self.key;
        let mut child = Command::new(&post).arg(&args).arg(key).spawn()?;

        let status = child.wait().await?;
        info!("command {} run completed - {}", post, status);

        Ok(())
    }

    #[instrument(name = "core-pre", skip(self))]
    async fn pre(&self) -> Result<()> {
        if let Some(pre) = &self.pre {
            let args = serde_json::to_string(&self.cfg)?;
            //debug!("args as {}", args);

            let key = &self.key;
            let mut child = Command::new(&pre).arg(&args).arg(key).spawn()?;

            let status = child.wait().await?;
            info!("command {} run completed - {}", pre, status);
        } else {
            debug!("no command");
        }

        Ok(())
    }

    #[instrument(name = "core-key-apply", skip(self, db_conn))]
    async fn key_apply(&self, db_conn: &mut DbConnection, force: bool) -> Result<()> {
        let key = &self.key;
        if force == false && db_conn.exists::<&str, bool>(&key).await? == true {
            debug!("db key - {} exist", &key);
            return Ok(());
        }

        let args = serde_json::to_string(&self.cfg)?;
        debug!("args as {}", args);

        db_conn.set(&key, &args).await?;

        Ok(())
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct KapNetworkConfig {
    cfg: NetworkMenu,
    key: String,
    post: String,
    pre: Option<String>,
}

#[async_trait]
impl FactoryAction for KapNetworkConfig {
    #[instrument(name = "network-post", skip(self))]
    async fn post(&self) -> Result<()> {
        let post = &self.post;
        let args = serde_json::to_string(&self.cfg)?;
        //debug!("args as {}", args);

        let key = &self.key;
        let mut child = Command::new(&post).arg(&args).arg(key).spawn()?;

        let status = child.wait().await?;
        info!("command {} run completed - {}", post, status);

        Ok(())
    }

    #[instrument(name = "network-pre", skip(self))]
    async fn pre(&self) -> Result<()> {
        if let Some(pre) = &self.pre {
            let args = serde_json::to_string(&self.cfg)?;
            //debug!("args as {}", args);

            let key = &self.key;
            let mut child = Command::new(&pre).arg(&args).arg(key).spawn()?;

            let status = child.wait().await?;
            info!("pre - {} run completed - {}", pre, status);
        } else {
            debug!("no pre command");
        }

        Ok(())
    }

    #[instrument(name = "network-key-apply", skip(self, db_conn))]
    async fn key_apply(&self, db_conn: &mut DbConnection, force: bool) -> Result<()> {
        let key = &self.key;
        if force == false && db_conn.exists::<&str, bool>(&key).await? == true {
            debug!("db key - {} exist", &key);
            return Ok(());
        }

        let args = serde_json::to_string(&self.cfg)?;
        debug!("args as {}", args);

        db_conn.set(&key, &args).await?;

        Ok(())
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct KapPorConfig {
    cfg: PorMenu,
    key: String,
    post: Option<String>,
    pre: Option<String>,
}

#[async_trait]
impl FactoryAction for KapPorConfig {
    #[instrument(name = "por-post", skip(self))]
    async fn post(&self) -> Result<()> {
        if let Some(post) = &self.post {
            let args = serde_json::to_string(&self.cfg)?;
            //debug!("args as {}", args);

            let key = &self.key;
            let mut child = Command::new(&post).arg(&args).arg(key).spawn()?;

            let status = child.wait().await?;
            info!("post - {} run completed - {}", post, status);
        } else {
            debug!("no post command");
        }

        Ok(())
    }

    #[instrument(name = "por-pre", skip(self))]
    async fn pre(&self) -> Result<()> {
        if let Some(pre) = &self.pre {
            let args = serde_json::to_string(&self.cfg)?;
            //debug!("args as {}", args);

            let key = &self.key;
            let mut child = Command::new(&pre).arg(&args).arg(key).spawn()?;

            let status = child.wait().await?;
            info!("pre - {} run completed - {}", pre, status);
        } else {
            debug!("no pre command");
        }

        Ok(())
    }

    #[instrument(name = "por-key-apply", skip(self, db_conn))]
    async fn key_apply(&self, db_conn: &mut DbConnection, force: bool) -> Result<()> {
        let key = &self.key;
        if force == false && db_conn.exists::<&str, bool>(&key).await? == true {
            debug!("db key - {} exist", &key);
            return Ok(());
        }

        let args = serde_json::to_string(&self.cfg)?;
        debug!("args as {}", args);

        db_conn.set(&key, &args).await?;

        Ok(())
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct KapBossConfig {
    cfg: BossMenu,
    key: String,
    post: Option<String>,
}

#[async_trait]
impl FactoryAction for KapBossConfig {
    #[instrument(name = "boss-post", skip(self))]
    async fn post(&self) -> Result<()> {
        if let Some(post) = &self.post {
            let args = serde_json::to_string(&self.cfg)?;
            //debug!("args as {}", args);

            let key = &self.key;
            let mut child = Command::new(&post).arg(&args).arg(key).spawn()?;

            let status = child.wait().await?;
            info!("command {} run completed - {}", post, status);
        } else {
            debug!("no post command");
        }

        Ok(())
    }

    #[instrument(name = "boss-pre", skip(self))]
    async fn pre(&self) -> Result<()> {
        debug!("no pre command");
        Ok(())
    }

    #[instrument(name = "boss-key-apply", skip(self, db_conn))]
    async fn key_apply(&self, db_conn: &mut DbConnection, force: bool) -> Result<()> {
        let key = &self.key;
        if force == false && db_conn.exists::<&str, bool>(&key).await? == true {
            debug!("db key - {} exist", &key);
            return Ok(());
        }

        let args = serde_json::to_string(&self.cfg)?;
        debug!("args as {}", args);

        db_conn.set(&key, &args).await?;

        Ok(())
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct KapCmpConfig {
    cfg: CmpMenu,
    key: String,
    post: String,
}

#[async_trait]
impl FactoryAction for KapCmpConfig {
    #[instrument(name = "cmp-post", skip(self))]
    async fn post(&self) -> Result<()> {
        let post = &self.post;
        let args = serde_json::to_string(&self.cfg)?;
        //debug!("args as {}", args);

        let key = &self.key;
        let mut child = Command::new(&post).arg(&args).arg(key).spawn()?;

        let status = child.wait().await?;
        info!("command {} run completed - {}", post, status);

        Ok(())
    }

    #[instrument(name = "cmp-pre", skip(self))]
    async fn pre(&self) -> Result<()> {
        debug!("no pre command");
        Ok(())
    }

    #[instrument(name = "cmp-key-apply", skip(self, db_conn))]
    async fn key_apply(&self, db_conn: &mut DbConnection, force: bool) -> Result<()> {
        let key = &self.key;
        if force == false && db_conn.exists::<&str, bool>(&key).await? == true {
            debug!("db key - {} exist", &key);
            return Ok(());
        }

        let args = serde_json::to_string(&self.cfg)?;
        debug!("args as {}", args);

        db_conn.set(&key, &args).await?;
        Ok(())
    }
}

#[instrument(name = "recovery", skip(cfg))]
async fn main_task(cfg: KapFactory, force: bool) -> Result<()> {
    debug!("cfg content as {:#?}", cfg);

    let mut db_conn = redis::Client::open(&*cfg.core.cfg.database_url)?
        .get_async_connection()
        .await?;
    //let db_conn = Arc::new(Mutex::new(db_conn));

    _ = cfg.core.run(&mut db_conn, force).await?;
    _ = cfg.network.run(&mut db_conn, force).await?;
    _ = cfg.por.run(&mut db_conn, force).await?;
    _ = cfg.boss.run(&mut db_conn, force).await?;
    _ = cfg.cmp.run(&mut db_conn, force).await?;

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

#[tokio::main]
async fn main() -> Result<(), MyError> {
    let opt = Opt::parse();
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
