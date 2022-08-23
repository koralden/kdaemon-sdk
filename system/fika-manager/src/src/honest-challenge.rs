use anyhow::Result;
use clap::Parser;
use tracing::{debug, instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use chrono::prelude::*;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[clap(
    name = "fika-honest-challenge",
    about = "FIKA Honest Challenge",
    version = "0.0.1",
)]
struct Opt {
    #[clap(short = 's', long = "timestamp")]
    timestamp: Option<DateTime<Utc>>,

    #[clap(short = 'c', long = "cron")]
    cron: Option<PathBuf>,

    #[clap(short = 'l', long = "log-level", default_value = "info")]
    log_level: String,

    #[clap(short, long, action)]
    tasks: bool,

    #[clap(short, long, action)]
    rfc3339: bool,
}

#[instrument(name = "timestamp", )]
async fn do_timestamp(t: DateTime<Utc>) -> Result<()> {
    debug!("DateTime - {:?} to Timestamp - {}", t, t.timestamp());
    println!("{}", t.timestamp());
    Ok(())
}

#[instrument(name = "rfc3339", )]
async fn do_rfc3339() -> Result<()> {
    let now = Utc::now();
    println!("{}", now.to_rfc3339_opts(SecondsFormat::Secs, false));
    Ok(())
}

#[instrument(name = "cron", )]
async fn do_cron(p: PathBuf) -> Result<()> {
    unimplemented!()
}

#[instrument(name = "task", )]
async fn do_tasks(cron: Option<PathBuf>) -> Result<()> {
    unimplemented!()
}

//pub type MyError = Box<dyn std::error::Error + Send + Sync>;
fn set_up_logging(log_level: &str) -> Result<()/*, MyError*/> {
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
async fn main() -> Result<()> {
    let opt = Opt::parse();
    set_up_logging(&opt.log_level)?;

    if let Some(t) = opt.timestamp {
        return do_timestamp(t).await;
    }
    if opt.rfc3339 {
        return do_rfc3339().await;
    }
    if opt.tasks {
        return do_tasks(opt.cron).await;
    }
    if let Some(p) = opt.cron {
        return do_cron(p).await;
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
