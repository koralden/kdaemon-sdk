use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Result};
use tokio::fs;
use tracing::{/*debug, error, info, instrument, */warn};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[allow(dead_code)]
pub struct KdaemonConfig {
    pub core: KCoreConfig,
    pub network: KNetworkConfig,
    pub por: KPorConfig,
    pub boss: KBossConfig,
    pub cmp: KCmpConfig,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[allow(dead_code)]
pub struct KCoreConfig {
    pub wallet_address: String,
    pub mac_address: String,
    pub serial_number: String,
    pub sku: String,
    pub database: String,
    pub user_wallet: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[allow(dead_code)]
pub struct KNetworkConfig {
    pub wan_type: u8,
    pub wan_username: Option<String>,
    pub wan_password: Option<String>,
    pub wifi_ssid: String,
    pub wifi_password: Option<String>,
    pub password_overwrite: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[allow(dead_code)]
pub struct KPorConfig {
    pub state: bool,
    pub nickname: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[allow(dead_code)]
pub struct KBossConfig {
    pub root_url: String,
    pub otp_path: String,
    pub ap_token_path: String,
    pub hcs_path: String,
    pub ap_hcs_path: String,
    pub ap_info_path: String,

    pub access_token: String,
    pub ap_access_token: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[allow(dead_code)]
pub struct KCmpConfig {
    pub endpoint: String,
    pub port: u32,

    pub thing: Option<String>,
    pub cert: String,
    pub private: String,
    pub ca: String,
}

impl KdaemonConfig {
    pub async fn build_from(path: &str) -> Result<Self> {
        let cfg = fs::read_to_string(path).await?;
        toml::from_str(&cfg).or_else(|e| Err(anyhow!(e)))
    }
}

impl KCmpConfig {
    pub fn apply_thing_name(&mut self, name: Option<String>) -> Result<()> {
        if self.thing.is_none() {
            self.thing= name;
        } else {
            warn!("thing-name-{:?} have forced", self.thing.as_ref());
        }
        Ok(())
    }

    pub async fn config_verify(&self) -> Result<()> {
        let file = fs::File::open(&self.cert).await?;
        let metadata = file.metadata().await?;
        if metadata.is_dir() || metadata.len() == 0 {
            return Err(anyhow!("{} invalid", &self.cert));
        }

        let file = fs::File::open(&self.private).await?;
        let metadata = file.metadata().await?;
        if metadata.is_dir() || metadata.len() == 0 {
            return Err(anyhow!("{} invalid", &self.private));
        }

        let file = fs::File::open(&self.ca).await?;
        let metadata = file.metadata().await?;
        if metadata.is_dir() || metadata.len() == 0 {
            return Err(anyhow!("{} invalid", &self.ca));
        }

        if self.thing.is_none() {
            return Err(anyhow!("{:?} invalid", self.thing));
        }

        Ok(())
    }
}
