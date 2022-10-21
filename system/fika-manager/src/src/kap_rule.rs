use anyhow::{anyhow, Result};
use tokio::time:: Duration;
use tokio::fs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::aws_iot::{RuleAwsIotDedicatedConfig, RuleAwsIotProvisionConfig};
use crate::publish_task::RuleConfigTask;

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
pub struct RuleConfig {
    pub core: RuleConfigCore,
    pub subscribe: Option<Vec<RuleConfigSubscribe>>,
    pub task: Option<Vec<RuleConfigTask>>,
    pub honest: Option<RuleHonestConfig>,
    pub aws: Option<RuleAwsIotConfig>,
}

impl RuleConfig {
    pub async fn build_from(path: &str) -> Result<Self> {
        let cfg = fs::read_to_string(path).await?;
        toml::from_str(&cfg).or_else(|e| Err(anyhow!(e)))
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
pub struct RuleConfigCore {
    pub thirdparty: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[allow(dead_code)]
pub struct RuleConfigSubscribe {
    pub topic: String,
    pub path: PathBuf,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
pub struct RuleHonestConfig {
    pub ok_cycle: Duration,
    pub fail_cycle: Duration,
    pub path: PathBuf,
    pub disable: Option<bool>,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
pub struct RuleAwsIotConfig {
    pub provision: Option<RuleAwsIotProvisionConfig>,
    pub dedicated: Option<RuleAwsIotDedicatedConfig>,
}

