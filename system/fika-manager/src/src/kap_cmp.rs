use serde::{Deserialize, Serialize};

//pub type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
pub struct CmpMenu {
    endpoint: String,
    port: u32,

    thing: String,
    cert: String,
    key: String,
    ca: String,
}
