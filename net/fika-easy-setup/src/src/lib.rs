/*pub mod kap_ez;
pub use kap_ez::NetworkMenu;
pub use kap_ez::PorMenu;*/

pub mod fas;
pub mod kap_daemon;
pub mod server_ctx;

pub const COOKIE_NAME: &str = "SESSION";

pub const API_PATH_SETUP_EASY: &str = "/setup/easy";
pub const API_PATH_AUTH_SIMPLE: &str = "/login";
pub const API_PATH_PAIRING: &str = "/pairing";
pub const API_PATH_PAIRING_STATUS: &str = "/pairing/status";
pub const API_PATH_SHOW_EMOJI: &str = "/show/emoji";
pub const API_PATH_LOGOUT: &str = "/logout";
pub const API_PATH_SYSTEM_CHECKING: &str = "/system/checking";
pub const API_PATH_POR_WIFI: &str = "/por/wifi";
pub const API_PATH_HONEST_CHALLENGE: &str = "/honest/challenge/:id";
pub const API_PATH_OPENNDS_FAS: &str = "/opennds/fas";
