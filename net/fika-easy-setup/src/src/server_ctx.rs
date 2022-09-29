use anyhow::{anyhow, Result};
use async_session::{MemoryStore, SessionStore};
use axum::{
    async_trait,
    extract::{
        rejection::TypedHeaderRejectionReason, Extension, FromRequest, RequestParts, TypedHeader,
    },
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use chrono::prelude::*;
use clap::Parser;
use http::header;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::iter::repeat_with;
use std::sync::Mutex;
use tracing::{debug, error, warn};

use crate::kap_daemon::{KNetworkConfig, KPorConfig, KdaemonConfig};
use crate::{API_PATH_AUTH_SIMPLE, COOKIE_NAME};

#[derive(Parser, Debug, Clone)]
#[clap(
    name = "fika-easy-setup",
    about = "FIKA easy setup server for pairing, challenge and  easy setup",
    version = "0.0.5"
)]
pub struct Opt {
    /// set the listen addr
    #[clap(short = 'a', long = "private-addr", default_value = "::1")]
    pub private_addr: String,

    /// set the listen port
    #[clap(short = 'p', long = "private-port", default_value = "8888")]
    pub private_port: u16,

    #[clap(long = "public-addr", default_value = "::1")]
    pub public_addr: String,

    /// set the listen port
    #[clap(long = "public-port", default_value = "8889")]
    pub public_port: u16,

    #[clap(long = "log-level", default_value = "info")]
    pub log_level: String,

    #[clap(short = 'r', long = "redis", default_value = "127.0.0.1:6379")]
    pub redis_addr: String,

    #[clap(long = "username"/*, default_value = "admin"*/)]
    pub client_username: Option<String>,

    #[clap(long = "password"/*, default_value = "tester"*/)]
    pub client_password: Option<String>,

    #[clap(short = 'w', long = "wallet")]
    pub wallet_addr: Option<String>,

    #[clap(long = "static-dir", default_value = "../templates")]
    pub static_dir: String,

    #[clap(long = "certificate")]
    pub certificate: Option<String>,
    #[clap(long = "private-key")]
    pub private_key: Option<String>,

    #[clap(long = "access-token")]
    pub access_token: Option<String>,
    #[clap(long = "access-token-ap")]
    pub access_token_ap: Option<String>,
    #[clap(long = "mac-address")]
    pub mac_address: Option<String>,

    #[clap(long = "fas-port", default_value = "8887")]
    pub fas_port: u16,
    #[clap(long = "fas-key", default_value = "5290676855")]
    pub fas_key: String,
    #[clap(long = "auth-dir", default_value = "opennds_auth")]
    pub auth_dir: String,

    #[clap(short = 'c', long = "config", default_value = "/userdata/kdaemon.toml")]
    pub config: String,
}

pub struct AuthRedirect(bool);

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        if self.0 == false {
            Redirect::temporary(API_PATH_AUTH_SIMPLE).into_response()
        } else {
            let resp = json!({"code": 401, "message": "Unauthorized"});
            (StatusCode::UNAUTHORIZED, Json(resp)).into_response()
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
pub struct SessionUser {
    pub name: String,
    pub password: String,
}

#[async_trait]
impl<B> FromRequest<B> for SessionUser
where
    B: Send,
{
    // If anything goes wrong or no session is found, redirect to the auth page
    type Rejection = AuthRedirect;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let is_json = if check_application_json(req).is_ok() {
            true
        } else {
            false
        };

        let Extension(store) = Extension::<MemoryStore>::from_request(req)
            .await
            .expect("`MemoryStore` extension is missing");

        let cookies = TypedHeader::<headers::Cookie>::from_request(req)
            .await
            .map_err(|e| match *e.name() {
                header::COOKIE => match e.reason() {
                    TypedHeaderRejectionReason::Missing => AuthRedirect(is_json),
                    _ => panic!("unexpected error getting Cookie header(s): {}", e),
                },
                _ => panic!("unexpected error getting cookies: {}", e),
            })?;
        let session_cookie = cookies.get(COOKIE_NAME).ok_or(AuthRedirect(is_json))?;

        let session = store
            .load_session(session_cookie.to_string())
            .await
            .unwrap()
            .ok_or(AuthRedirect(is_json))?;

        let user = session
            .get::<SessionUser>("user")
            .ok_or(AuthRedirect(is_json))?;

        Ok(user)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct KApOtp {
    otp: String,
    /*#[serde(with = "my_date_format")]
    invalid_time: DateTime<Local>,*/
    invalid_time: DateTime<Utc>,
    code: u16,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
pub struct BossApInfoData {
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KAppOtp {
    pub ap_wallet: String,
    pub otp: String,
    pub url: String,
    //ap_mac: Option<String>, //XXX remove MAC
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct InternalServerCtx {
    otp: String,
    code: u16,
    invalid_time: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerCtx {
    api_url: String,
    otp_path: String,
    ap_info_path: String,
    access_token: String,
    access_token_ap: String,
    pub wallet: String,
    mac: String,

    /* authenticate */
    login_name: Option<String>,
    login_password: Option<String>,

    internal: Mutex<InternalServerCtx>,
    daemon_cfg: Mutex<Option<KdaemonConfig>>,
}

impl ServerCtx {
    pub async fn build_from(opt: &Opt) -> Self {
        let daemon_cfg = KdaemonConfig::build_from(&opt.config).await.ok();

        let wallet = opt.wallet_addr.as_ref().map_or(
            daemon_cfg
                .as_ref()
                .map_or("CHANGEME".to_string(), |c| c.core.wallet_address.clone()),
            |w| w.clone(),
        );

        let mac = opt.mac_address.as_ref().map_or(
            daemon_cfg
                .as_ref()
                .map_or("CHANGEME".to_string(), |c| c.core.mac_address.clone()),
            |m| m.clone(),
        );

        let access_token = opt.access_token.as_ref().map_or(
            daemon_cfg
                .as_ref()
                .map_or("CHANGEME".to_string(), |c| c.boss.access_token.clone()),
            |t| t.clone(),
        );

        let access_token_ap = opt.access_token_ap.as_ref().map_or(
            daemon_cfg.as_ref().map_or("CHANGEME".to_string(), |c| {
                c.boss
                    .ap_access_token
                    .as_ref()
                    .map_or("CHANGEME".to_string(), |t| t.clone())
            }),
            |t| t.clone(),
        );

        let api_url = daemon_cfg
            .as_ref()
            .map_or("CHANGEME".to_string(), |c| c.boss.root_url.clone());

        let otp_path = daemon_cfg
            .as_ref()
            .map_or("CHANGEME".to_string(), |c| c.boss.otp_path.clone());

        let ap_info_path = daemon_cfg
            .as_ref()
            .map_or("CHANGEME".to_string(), |c| c.boss.ap_info_path.clone());

        ServerCtx {
            api_url,
            access_token,
            access_token_ap,
            otp_path,
            ap_info_path,
            wallet,
            mac,
            login_name: opt.client_username.clone(),
            login_password: opt.client_password.clone(),

            internal: Mutex::new(InternalServerCtx {
                otp: repeat_with(fastrand::alphanumeric).take(6).collect(),
                invalid_time: Utc::now(), /* + chrono::Duration::seconds(300)*/
                code: 404,
            }),

            daemon_cfg: Mutex::new(daemon_cfg),
        }
    }

    fn set_core_cfg_user_wallet(&self, user_wallet: Option<String>) -> Result<()> {
        if let Ok(mut daemon_cfg) = self.daemon_cfg.lock() {
            match *daemon_cfg {
                Some(ref mut c) => {
                    c.core.user_wallet = user_wallet;
                    Ok(())
                }
                None => Err(anyhow!("KDaemonConfig not exist!")),
            }
        } else {
            Err(anyhow!("KDaemonConfig mutex lock fail"))
        }
    }

    pub fn get_network_cfg(&self) -> Result<KNetworkConfig> {
        let daemon_cfg = self.daemon_cfg.lock().unwrap();

        let cfg = match *daemon_cfg {
            Some(ref c) => c.network.clone(),
            None => KNetworkConfig {
                password_overwrite: Some("on".to_string()),
                ..Default::default()
            },
        };

        Ok(cfg)
    }

    pub fn set_network_cfg(&self, cfg: &KNetworkConfig) -> Result<()> {
        if let Ok(mut daemon_cfg) = self.daemon_cfg.lock() {
            match *daemon_cfg {
                Some(ref mut c) => {
                    c.network = cfg.clone();
                    Ok(())
                }
                None => Err(anyhow!("KDaemonConfig not exist!")),
            }
        } else {
            Err(anyhow!("KDaemonConfig mutex lock fail"))
        }
    }

    #[allow(dead_code)]
    pub fn get_por_cfg(&self) -> Result<KPorConfig> {
        let daemon_cfg = self.daemon_cfg.lock().unwrap();

        let cfg = match *daemon_cfg {
            Some(ref c) => c.por.clone(),
            None => KPorConfig {
                ..Default::default()
            },
        };

        Ok(cfg)
    }

    pub fn set_por_cfg(&self, cfg: &KPorConfig) -> Result<()> {
        if let Ok(mut daemon_cfg) = self.daemon_cfg.lock() {
            match *daemon_cfg {
                Some(ref mut c) => {
                    c.por = cfg.clone();
                    Ok(())
                }
                None => Err(anyhow!("KDaemonConfig not exist!")),
            }
        } else {
            Err(anyhow!("KDaemonConfig mutex lock fail"))
        }
    }

    fn set_por_cfg_nickname(&self, nickname: Option<String>) -> Result<()> {
        if let Ok(mut daemon_cfg) = self.daemon_cfg.lock() {
            match *daemon_cfg {
                Some(ref mut c) => {
                    c.por.nickname = nickname;
                    Ok(())
                }
                None => Err(anyhow!("KDaemonConfig not exist!")),
            }
        } else {
            Err(anyhow!("KDaemonConfig mutex lock fail"))
        }
    }

    pub async fn get_mac_address(&self, skip: usize) -> String {
        let mac: String = self
            .mac
            .split(":")
            .skip(skip)
            .map(|m| m.to_uppercase())
            .fold(String::from("-"), |all, m| all + m.as_str());
        mac
    }

    pub async fn get_boss_otp(&self) -> Result<String> {
        /*let mac = String::from("A1:A2:33:44:55:66");
        let invalid_time;
        {
            let internal = self.internal.lock().unwrap();
            invalid_time = internal.invalid_time;
        }*/

        /*if Utc::now() >= invalid_time */
        {
            let url = format!("{}/{}", &self.api_url, &self.otp_path);
            let client = reqwest::Client::new();
            let data = client
                .get(&url)
                //.bearer_auth(token.access_token().secret())
                .header("ACCESSTOKEN", &self.access_token)
                .header("ACCESSTOKEN-AP", &self.access_token_ap)
                .query(&[("ap_wallet", &self.wallet) /*, ("ap_mac", &mac)*/])
                .send()
                .await?
                .json::<KApOtp>()
                .await?;

            debug!("{} get as {:?}", url, data);

            {
                let mut internal = self.internal.lock().unwrap();

                internal.otp = data.otp.clone();
                internal.invalid_time = data.invalid_time;
                internal.code = data.code;

                Ok(data.otp)
            }
        } /* else {
              let internal = self.internal.lock().unwrap();

              Ok(internal.otp.clone())
          }*/
    }

    async fn get_boss_api_info(&self) -> Result<BossApInfoData> {
        let url = format!("{}/{}", &self.api_url, &self.ap_info_path);

        let mut map = HashMap::new();
        map.insert("ap_wallet", &self.wallet);

        let client = reqwest::Client::new();
        let mut response = client
            .get(&url)
            //.bearer_auth(token.access_token().secret())
            .header("ACCESSTOKEN", &self.access_token)
            .header("ACCESSTOKEN-AP", &self.access_token_ap)
            .json(&map)
            .send()
            .await?
            .json::<Value>()
            .await?;

        debug!("{} get json-{:?}", url, response);

        match serde_json::from_value::<u16>(response["code"].take()) {
            Ok(code) => {
                if code == 200 {
                    serde_json::from_value::<BossApInfoData>(response["data"].take()).or_else(|e| {
                        Err(anyhow::anyhow!(format!("invalid response format({})", e)))
                    })
                } else {
                    let m = serde_json::from_value::<String>(response["message"].take())
                        .unwrap_or("invalid response format(no message)".to_string());
                    Err(anyhow::anyhow!(m))
                }
            }
            _ => Err(anyhow::anyhow!(
                "invalid response format(no code)".to_owned()
            )),
        }
    }

    async fn cache_boss_api_info(
        &self,
        conn: Result<redis::aio::Connection>,
    ) -> Result<BossApInfoData> {
        let key_set = "kap.boss.ap.info";
        if let Ok(mut conn) = conn {
            if let Ok(bs) = conn.get::<&str, String>(key_set).await {
                /* updted via MQTT/subscribe in fika-manager */
                serde_json::from_str::<BossApInfoData>(&bs).or(Err(anyhow!("json convert fail")))
            } else {
                /*XXX trandition BOSS/polling flow,
                 * just enable until oss->cmp->kap ready */
                match self.get_boss_api_info().await {
                    Ok(info) => {
                        let msg = serde_json::to_string(&info).unwrap();
                        let ipc_key = "boss/ap/info";
                        if let Err(e) = conn.publish::<&str, &str, usize>(ipc_key, &msg).await {
                            error!("ipc publish {ipc_key}/{:?} error - {:?}", &msg, e);
                        }
                        Ok(info)
                    }
                    Err(e) => {
                        error!("call get_boss_api_info() fail - {e}");
                        Err(e)
                    }
                }
            }
        } else {
            self.get_boss_api_info().await
        }
    }

    pub async fn get_boss_owner(&self, conn: Result<redis::aio::Connection>) -> Result<String> {
        if let Ok(info) = self.cache_boss_api_info(conn).await {
            /* TODO if heavy loading? */
            _ = self.set_por_cfg_nickname(info.device_nickname.clone());
            _ = self.set_core_cfg_user_wallet(info.user_wallet.clone());

            if info.user_wallet.is_some() {
                return Ok(info.user_wallet.unwrap());
            }
        }
        Err(anyhow::anyhow!("user-wallet nonexist"))
    }

    pub fn as_app_query(&self, otp: Option<String>) -> Result<KAppOtp> {
        let otp = match otp {
            Some(o) => o,
            None => {
                let internal = self.internal.lock().unwrap();
                internal.otp.clone()
            }
        };

        let url = reqwest::Url::parse_with_params(
            &format!("{}/{}", &self.api_url, &self.otp_path),
            &[
                ("ap_wallet", &self.wallet),
                ("otp", &otp),
                //("ap_mac", &self.mac),
            ],
        )?;

        Ok(KAppOtp {
            ap_wallet: self.wallet.clone(),
            url: url.into(),
            otp,
            //ap_mac: Some(self.mac.clone()),
        })
    }

    pub fn get_shadow_password(&self, username: &str) -> Result<String> {
        match shadow::Shadow::from_name(username) {
            Some(s) => Ok(s.password),
            None => Err(anyhow::anyhow!("User {} password not found", username)),
        }
    }

    pub fn need_login(&self, user: Option<SessionUser>) -> Result<()> {
        debug!("need_login user {:?}", user);
        if user.is_none() {
            if let Ok(name) = env::var("LOGIN_NAME") {
                if let Ok(_) = env::var("LOGIN_PASSWORD") {
                    debug!("need_login LOGIN_PASSWORD for {}", name);
                    return Err(anyhow::anyhow!("User {} admin need login", name));
                }
            } else if let Some(name) = &self.login_name {
                if let Some(_) = &self.login_password {
                    debug!("need_login {:?} for {}", &self.login_password, name);
                    return Err(anyhow::anyhow!("User {} admin need login", name));
                }
            } else {
                if let Ok(spwd) = self.get_shadow_password("admin") {
                    if spwd.len() != 0 {
                        debug!("need_login shadow for {}", "admin");
                        return Err(anyhow::anyhow!("User admin need login"));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn do_login(&self, user: &str, passwd: &str) -> Result<()> {
        if let Ok(spassword) = self.get_shadow_password(user) {
            if spassword.len() != 0 && pwhash::unix::verify(&passwd, &spassword) == false {
                warn!("shadow permission denied or password not match");
                return Err(anyhow::anyhow!("Shadow password not match"));
            }
        } else if let Some(username) = &self.login_name {
            if username != user {
                warn!("user-name not match");
                return Err(anyhow::anyhow!("User-name not match"));
            }
        } else if let Ok(username) = env::var("LOGIN_NAME") {
            if &username != user {
                warn!("env user-name not match");
                return Err(anyhow::anyhow!("Env user-name not match"));
            }
        } else if let Some(password) = &self.login_password {
            if password != &passwd {
                warn!("password not match");
                return Err(anyhow::anyhow!("Password not match"));
            }
        } else if let Ok(password) = env::var("LOGIN_PASSWORD") {
            if &password != passwd {
                warn!("env password not match");
                return Err(anyhow::anyhow!("Env password not match"));
            }
        } else {
            warn!("user non-exist");
            return Err(anyhow::anyhow!("user non-exist"));
        }
        Ok(())
    }
}

pub fn check_application_json<B>(req: &RequestParts<B>) -> Result<()> {
    let content_type_header = req.headers().get(CONTENT_TYPE);
    let content_type = content_type_header.and_then(|value| value.to_str().ok());

    if let Some(content_type) = content_type {
        if content_type.starts_with("application/json") {
            Ok(())
        } else {
            Err(anyhow!("normal html"))
        }
    } else {
        Err(anyhow!("normal html"))
    }
}
