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
    pub ap_info_path: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
pub struct BossApInfoData {
    /*
    "ap_wallet": "...",
    "user_wallet": "...",
    "device_nickname": "...",
    "location_latitude": "24.8082",
    "location_longitude": "121.04",
    "location_zip": "302",
    "location_address": "...",
    "location_hint": "...",
    "init_time": "2022-08-24T12:32:26+0800",
    "update_time": "2022-08-24T12:32:26+0800",
    "last_hb_time": null,
    "user_nickname": ""
    */
    pub ap_wallet: Option<String>,
    pub user_wallet: Option<String>,
    pub device_nickname: Option<String>,
    pub location_latitude: Option<String>,
    pub location_longitude: Option<String>,
    pub location_zip: Option<String>,
    pub location_address: Option<String>,
    pub location_hint: Option<String>,
    pub init_time: Option<String>,
    pub update_time: Option<String>,
    pub last_hb_time: Option<String>,
    pub user_nickname: Option<String>,
}
