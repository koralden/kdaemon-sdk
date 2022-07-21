use serde::{Deserialize, Serialize};

//pub type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
pub struct CoreMenu {
    pub wallet_address: String,
    pub database_url: String,
}
