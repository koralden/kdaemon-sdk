use serde::{Deserialize, Serialize};

//pub type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
pub struct BossMenu {
    root_url: String,
    access_token: String,

    otp_url: String,
    ap_token_url: String,
    hcs_pair_url: String,
}
