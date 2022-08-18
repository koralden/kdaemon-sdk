use serde::{Deserialize, Serialize};

//pub type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
pub struct BossMenu {
    pub root_url: String,
    pub access_token: String,

    pub otp_path: String,
    pub ap_token_path: String,
    pub hcs_path: String,
    pub ap_hcs_path: String,
}
