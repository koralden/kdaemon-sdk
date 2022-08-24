use serde::{Deserialize, Serialize};

//pub type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
pub struct BossMenu {
    root_url: String,
    access_token: String,

    otp_path: String,
    ap_token_path: String,
    hcs_path: String,
    ap_hcs_path: String,
    ap_info_path: String,
}
