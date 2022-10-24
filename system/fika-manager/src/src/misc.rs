use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};
use serde_json::{json, Value};
use std::collections::HashMap;
use tracing::{debug, error, instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(feature = "wallet")]
use ethers::prelude::*;

use chrono::prelude::*;
//use std::path::PathBuf;

use crate::kap_daemon::KdaemonConfig;

#[derive(Args, Debug)]
#[clap(about = "Curl-like")]
struct CurlAnyOpt {
    #[clap(
        short = 'o',
        long = "output",
        default_value = "/userdata/crypto_wallet.json"
    )]
    output: String,
}

#[derive(Args, Debug)]
struct ApWalletOpt {
    #[clap(help = r#"{"who": $who, "where": $where, "comment": $comment }"#)]
    json: Value,
}

#[derive(Args, Debug)]
struct ApHcsOpt {
    #[clap(help = r#"{"ap_wallet":$wallet,"hcs_token":$hcs_token,"hash":$hash}"#)]
    json: Value,
}

#[derive(Subcommand, Debug)]
#[clap(about = "Curl/Boss")]
enum CurlBossPath {
    GetApToken,
    GetOtp,
    GetHcs,
    GetApInfo,
    GetApWallet(ApWalletOpt),
    PostApHcs(ApHcsOpt),
}

#[derive(Args, Debug)]
#[clap(about = "Boss web api")]
pub struct CurlBossOpt {
    #[clap(subcommand)]
    class: CurlBossPath,

    #[clap(short = 'c', long = "config", default_value = "/userdata/kdaemon.toml")]
    config: String,

    #[clap(short = 'u', long = "root-url")]
    root: Option<String>,

    #[clap(short = 'r', long = "access-region")]
    access_region: Option<String>,

    #[clap(short = 't', long = "ap-access-token")]
    access_token: Option<String>,

    #[clap(short = 'w', long = "ap-wallet")]
    wallet: Option<String>,

    #[clap(short = 'p', long = "api-path")]
    path: Option<String>,
}

#[derive(Args, Debug, Clone)]
#[clap(about = "Generate Wallet")]
pub struct GenerateOpt {
    #[clap(short = 'o', long = "output")]
    output: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum WalletCommand {
    Generate(GenerateOpt),
    //Transact(TransactOpt),
    //Balance(BalanceOpt),
}

#[derive(Args, Debug)]
#[clap(about = "Timestamp now")]
pub struct TimestampOpt {
    timestamp: DateTime<Utc>,
}

#[derive(Args, Debug)]
#[clap(about = "FIKA Time Toolset")]
pub struct TimeToolOpt {
    #[clap(subcommand)]
    commands: TimeToolCommand,

    #[clap(short = 'l', long = "log-level", default_value = "info")]
    log_level: String,
}

#[derive(Subcommand, Debug)]
enum TimeToolCommand {
    Timestamp(TimestampOpt),
    Rfc3339,
}

#[instrument(name = "timestamp")]
async fn do_timestamp(t: DateTime<Utc>) -> Result<()> {
    debug!("DateTime - {:?} to Timestamp - {}", t, t.timestamp());
    println!("{}", t.timestamp());
    Ok(())
}

#[instrument(name = "rfc3339")]
async fn do_rfc3339() -> Result<()> {
    let now = Utc::now();
    println!("{}", now.to_rfc3339_opts(SecondsFormat::Secs, false));
    Ok(())
}

#[allow(dead_code)]
#[instrument(name = "curl")]
async fn do_curl(c: CurlAnyOpt) -> Result<()> {
    unimplemented!()
}

#[cfg(feature = "boss-api")]
pub async fn boss_tools(b: CurlBossOpt) -> Result<()> {
    let cfg = KdaemonConfig::build_from(&b.config).await?;
    let core = cfg.core;
    let boss = cfg.boss;

    let root_url = if let Some(root) = b.root {
        root
    } else {
        boss.root_url
    };

    let region = if let Some(region) = b.access_region {
        region
    } else {
        boss.access_token
    };

    let token = if let Some(token) = b.access_token {
        Some(token)
    } else {
        boss.ap_access_token
    };

    let wallet = if let Some(wallet) = b.wallet {
        Some(wallet)
    } else {
        core.wallet_address
    };

    let client = reqwest::Client::new();

    match b.class {
        CurlBossPath::GetApToken => {
            let path = if let Some(path) = b.path {
                path
            } else {
                boss.ap_token_path
            };

            let wallet = if let Some(w) = wallet {
                w
            } else {
                return Err(anyhow::anyhow!("wallet-address invalid"));
            };

            let url = format!("{}/{}", root_url, &path);

            let response = client
                .get(&url)
                .header("ACCESSTOKEN", &region)
                .query(&[("ap_wallet", &wallet)])
                .send()
                .await?
                .json::<Value>()
                .await?;

            debug!(
                r#"[kap][boss] curl -s -H "ACCESSTOKEN:{}" -X GET '{}?ap_wallet={}' => {:?}"#,
                &region, &url, &wallet, response
            );

            if response["code"] == 200 {
                if let Some(str) = response["ap_token"].as_str() {
                    println!("{}", str);
                } else {
                    return Err(anyhow::anyhow!("{} slice fail", response["ap_token"]));
                }
            } else {
                return Err(anyhow::anyhow!(
                    "{} [{}]",
                    response["message"],
                    response["code"]
                ));
            }
        }
        CurlBossPath::PostApHcs(map) => {
            if token.is_none() {
                error!("[kap][boss] ap-acess-token not exist");
                return Err(anyhow!("[kap][boss] ap-acess-token not exist"));
            }

            let path = if let Some(path) = b.path {
                path
            } else {
                boss.ap_hcs_path
            };

            let wallet = if let Some(w) = wallet {
                w
            } else {
                return Err(anyhow::anyhow!("wallet-address invalid"));
            };

            let url = format!("{}/{}", root_url, &path);
            let token = token.unwrap();

            let response = client
                .post(&url)
                .header("ACCESSTOKEN", &region)
                .header("ACCESSTOKEN-AP", &token)
                .json(&map.json)
                .query(&[("ap_wallet", &wallet)])
                .send()
                .await?
                .json::<Value>()
                .await?;

            debug!(
                r#"[kap][boss] curl -s -H "ACCESSTOKEN:{}" -H "ACCESSTOKEN-AP:{}" -X POST -d '{:?}' '{}?ap_wallet={}' => {:?}"#,
                &region,
                &token,
                &map.json.to_string(),
                &url,
                &wallet,
                response
            );

            if response["code"] == 200 {
                println!("{}", response["data"]);
            } else {
                return Err(anyhow::anyhow!(
                    "{} [{}]",
                    response["message"],
                    response["code"]
                ));
            }
        }
        CurlBossPath::GetOtp => {
            if token.is_none() {
                error!("[kap][boss] ap-acess-token not exist");
                return Err(anyhow!("[kap][boss] ap-acess-token not exist"));
            }

            let path = if let Some(path) = b.path {
                path
            } else {
                boss.otp_path
            };

            let wallet = if let Some(w) = wallet {
                w
            } else {
                return Err(anyhow::anyhow!("wallet-address invalid"));
            };

            let token = token.unwrap();
            let url = format!("{}/{}", root_url, &path);

            let response = client
                .get(&url)
                .header("ACCESSTOKEN", &region)
                .header("ACCESSTOKEN-AP", &token)
                .query(&[("ap_wallet", &wallet)])
                .send()
                .await?
                .json::<Value>()
                .await?;

            debug!(
                r#"[kap][boss] curl -s -H "ACCESSTOKEN:{}" -H "ACCESSTOKEN-AP:{}" -X GET '{}?ap_wallet={}' => {:?}"#,
                &region, &token, &url, &wallet, response
            );

            if response["code"] == 200 {
                println!("{}", response);
            } else {
                return Err(anyhow::anyhow!(
                    "{} [{}]",
                    response["message"],
                    response["code"]
                ));
            }
        }
        CurlBossPath::GetHcs => {
            if token.is_none() {
                error!("[kap][boss] ap-acess-token not exist");
                return Err(anyhow!("ap-acess-token not exist"));
            }

            let path = if let Some(path) = b.path {
                path
            } else {
                boss.hcs_path
            };

            let wallet = if let Some(w) = wallet {
                w
            } else {
                return Err(anyhow::anyhow!("wallet-address invalid"));
            };

            let token = token.unwrap();
            let url = format!("{}/{}", root_url, &path);

            let response = client
                .get(&url)
                .header("ACCESSTOKEN", &region)
                .header("ACCESSTOKEN-AP", &token)
                .query(&[("ap_wallet", &wallet)])
                .send()
                .await?
                .json::<Value>()
                .await?;

            debug!(
                r#"[kap][boss] curl -s -H "ACCESSTOKEN:{}" -H "ACCESSTOKEN-AP:{}" -X GET '{}?ap_wallet={}' => {:?}"#,
                &region, &token, &url, &wallet, response
            );

            if response["code"] == 200 {
                println!("{}", response["hcs"]);
            } else {
                return Err(anyhow::anyhow!(
                    "{} [{}]",
                    response["message"],
                    response["code"]
                ));
            }
        }
        CurlBossPath::GetApInfo => {
            if token.is_none() {
                error!("[kap][boss] ap-acess-token not exist");
                return Err(anyhow!("[kap][boss] ap-acess-token not exist"));
            }

            let path = if let Some(path) = b.path {
                path
            } else {
                boss.ap_info_path
            };

            let wallet = if let Some(w) = wallet {
                w
            } else {
                return Err(anyhow::anyhow!("wallet-address invalid"));
            };

            let token = token.unwrap();
            let url = format!("{}/{}", root_url, &path);
            let mut map = HashMap::new();
            map.insert("ap_wallet", &wallet);

            let response = client
                .get(&url)
                .header("ACCESSTOKEN", &region)
                .header("ACCESSTOKEN-AP", &token)
                .json(&map)
                .send()
                .await?
                .json::<Value>()
                .await?;

            debug!(
                r#"[kap][boss] curl -s -H "ACCESSTOKEN:{}" -H "ACCESSTOKEN-AP:{}" -X GET -d '{}' '{}' => {:?}"#,
                &region,
                &token,
                &json!(&map).to_string(),
                &url,
                response
            );

            if response["code"] == 200 {
                println!("{}", response["data"]);
            } else {
                return Err(anyhow::anyhow!(
                    "{} [{}]",
                    response["message"],
                    response["code"]
                ));
            }
        }
        CurlBossPath::GetApWallet(map) => {
            let path = if let Some(path) = b.path {
                path
            } else {
                "v0/device/get_eth_wallet".to_string()
            };

            let url = format!("{}/{}", root_url, &path);

            let response = client
                .get(&url)
                .header("ACCESSTOKEN", &region)
                .json(&map.json)
                .send()
                .await?
                .json::<Value>()
                .await?;

            debug!(
                r#"[kap][boss] curl -s -H "ACCESSTOKEN:{}" -X GET -d {:?} '{}' => {:?}"#,
                &region,
                &map.json.to_string(),
                &url,
                response
            );

            if response["code"] == 200 {
                if let Some(str) = response["data"]["wallet"].as_str() {
                    println!("{}", str);
                } else {
                    return Err(anyhow::anyhow!("{} slice fail", response["data"]["wallet"]));
                }
            } else {
                return Err(anyhow::anyhow!(
                    "{} [{}]",
                    response["message"],
                    response["code"]
                ));
            }
        }
    }

    Ok(())
}

#[cfg(feature = "wallet")]
#[instrument(name = "wallet")]
pub async fn wallet_tools(w: WalletCommand) -> Result<()> {
    match w {
        WalletCommand::Generate(_cfg) => {
            let wallet = LocalWallet::new(&mut rand::thread_rng());
            println!("{:?}", wallet.address());
        }
    }
    Ok(())
}

//pub type MyError = Box<dyn std::error::Error + Send + Sync>;
fn set_up_logging(log_level: &str) -> Result<() /*, MyError*/> {
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
pub async fn time_tools(opt: TimeToolOpt) -> Result<()> {
    set_up_logging(&opt.log_level)?;

    match opt.commands {
        TimeToolCommand::Timestamp(t) => {
            do_timestamp(t.timestamp).await?;
        }
        TimeToolCommand::Rfc3339 => {
            do_rfc3339().await?;
        }
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
