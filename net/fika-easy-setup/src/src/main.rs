//! Ref axum/example/OAuth (Discord) implementation.
//!
//! 1) Create a new application at <https://discord.com/developers/applications>
//! 2) Visit the OAuth2 tab to get your CLIENT_ID and CLIENT_SECRET
//! 3) Add a new redirect URI (for this example: `http://127.0.0.1:3000/auth/authorized`)
//! 4) Run with the following (replacing values appropriately):
//! ```not_rust
//! CLIENT_ID=REPLACE_ME CLIENT_SECRET=REPLACE_ME cargo run -p example-oauth
//! ```

use anyhow::{anyhow, Result};
use async_session::{MemoryStore, Session, SessionStore};
use axum::{
    async_trait,
    extract::Form,
    extract::{
        rejection::TypedHeaderRejectionReason, ConnectInfo, Extension, FromRequest, Path, Query,
        RequestParts, TypedHeader,
    },
    http::{header::CONTENT_TYPE, header::SET_COOKIE, HeaderMap, StatusCode},
    response::Html,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use axum_macros::debug_handler;
use axum_server::tls_rustls::RustlsConfig;
use chrono::prelude::*;
use clap::Parser;
use futures_util::{StreamExt as _/*, TryFutureExt*/};
use http::header;
use qrcode::render::svg;
use qrcode::QrCode;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::iter::repeat_with;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::{env, net::SocketAddr};
use tokio::time::{self, Duration};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use fika_easy_setup::fas;
use fika_easy_setup::kap_boss::{BossApInfoData, BossMenu};
use fika_easy_setup::kap_core::CoreMenu;

#[derive(Parser, Debug, Clone)]
#[clap(
    name = "fika-easy-setup",
    about = "FIKA easy setup server for pairing, challenge and  easy setup",
    version = "0.0.2"
)]
struct Opt {
    /// set the listen addr
    #[clap(short = 'a', long = "private-addr", default_value = "::1")]
    private_addr: String,

    /// set the listen port
    #[clap(short = 'p', long = "private-port", default_value = "8888")]
    private_port: u16,

    #[clap(long = "public-addr", default_value = "::1")]
    public_addr: String,

    /// set the listen port
    #[clap(long = "public-port", default_value = "8889")]
    public_port: u16,

    #[clap(long = "log-level", default_value = "info")]
    log_level: String,

    #[clap(short = 'r', long = "redis", default_value = "127.0.0.1:6379")]
    redis_addr: String,

    #[clap(long = "username"/*, default_value = "admin"*/)]
    client_username: Option<String>,

    #[clap(long = "password"/*, default_value = "tester"*/)]
    client_password: Option<String>,

    #[clap(short = 'w', long = "wallet")]
    wallet_addr: Option<String>,

    #[clap(long = "static-dir", default_value = "../templates")]
    static_dir: String,

    #[clap(long = "certificate")]
    certificate: Option<String>,
    #[clap(long = "private-key")]
    private_key: Option<String>,

    #[clap(long = "api-url")]
    api_url: Option<String>,
    #[clap(long = "access-token")]
    access_token: Option<String>,
    #[clap(long = "access-token-ap")]
    access_token_ap: Option<String>,
    #[clap(long = "otp-path")]
    otp_path: Option<String>,
    #[clap(long = "mac-address")]
    mac_address: Option<String>,

    #[clap(long = "fas-port", default_value = "8887")]
    fas_port: u16,
    #[clap(long = "fas-key", default_value = "5290676855")]
    fas_key: String,
    #[clap(long = "auth-dir", default_value = "opennds_auth")]
    auth_dir: String,
}

static COOKIE_NAME: &str = "SESSION";

static API_PATH_SETUP_EASY: &str = "/setup/easy";
static API_PATH_AUTH_SIMPLE: &str = "/login";
static API_PATH_PAIRING: &str = "/pairing";
static API_PATH_PAIRING_STATUS: &str = "/pairing/status";
static API_PATH_SHOW_EMOJI: &str = "/show/emoji";
static API_PATH_LOGOUT: &str = "/logout";
static API_PATH_SYSTEM_CHECKING: &str = "/system/checking";
static API_PATH_POR_WIFI: &str = "/por/wifi";
static API_PATH_HONEST_CHALLENGE: &str = "/honest/challenge/:id";
static API_PATH_OPENNDS_FAS: &str = "/opennds/fas";

#[tokio::main]
async fn main() {
    let opt = Opt::parse();
    let log_level = &opt.log_level;

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(move |_| format!("{},hyper=info,mio=info", log_level).into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let fas = tokio::spawn(fas::fas_service(
        opt.public_addr.clone(),
        opt.fas_port,
        opt.redis_addr.clone(),
        opt.fas_key.clone(),
        opt.auth_dir.clone(),
    ));

    let http = tokio::spawn(public_service(
        opt.public_addr.clone(),
        opt.public_port,
        opt.redis_addr.clone(),
        opt.wallet_addr.clone(),
        opt.certificate.clone(),
        opt.private_key.clone(),
    ));
    let https = tokio::spawn(private_service(opt));

    let _ = tokio::join!(https, http, fas);
}

async fn private_service(mut opt: Opt) {
    // `MemoryStore` is just used as an example. Don't use this in production.
    let store = MemoryStore::new();

    let redis_addr = format!("redis://{}/", opt.redis_addr);
    let cache = redis::Client::open(redis_addr).unwrap();

    let mut api_url = opt.api_url;
    let mut access_token = opt.access_token;
    let mut otp_path = opt.otp_path;
    let mut wallet = opt.wallet_addr;
    let mac = opt.mac_address;
    let mut access_token_ap = opt.access_token_ap;
    let mut ap_info_path = None;

    if let Ok(mut db_conn) = cache.get_async_connection().await {
        /*let wallet = wallet.map_or_else(|e| {
            let core = db_conn.get::<&str, String>("kap.core").await
                .or(Err("kap.core not found"))
                .and_then(|s| serde_json::from_str::<CoreMenu>(&s).or(Err("json convert fail")));
            /*if let Ok(core) = core {
                wallet = core.wallet_address;
            }*/
            core.map_or(None, |c| Some(c.wallet_address))
        }, |v| Some(v));*/

        let value = db_conn
            .get::<&str, String>("kap.core")
            .await
            .or(Err("kap.core not found"))
            .and_then(|s| serde_json::from_str::<CoreMenu>(&s).or(Err("json convert fail")));
        if let Ok(value) = value {
            wallet = wallet.or(Some(value.wallet_address));
        }
        let value = db_conn
            .get::<&str, String>("kap.boss")
            .await
            .or(Err("kap.boss not found"))
            .and_then(|s| serde_json::from_str::<BossMenu>(&s).or(Err("json convert fail")));
        if let Ok(value) = value {
            api_url = api_url.or(Some(value.root_url));
            access_token = access_token.or(Some(value.access_token));
            otp_path = otp_path.or(Some(value.otp_path));
            ap_info_path = Some(value.ap_info_path);
        }
        let value = db_conn.get::<&str, String>("kap.boss.ap.token").await;
        if let Ok(value) = value {
            access_token_ap = access_token_ap.or(Some(value));
        }
    }

    let otp = ServerCtx::new(
        api_url,
        otp_path,
        ap_info_path,
        access_token,
        access_token_ap,
        wallet,
        mac,
        opt.client_username.take(),
        opt.client_password.take(),
    );

    let app = Router::new()
        .route("/", get(index))
        .route(
            API_PATH_AUTH_SIMPLE,
            get(get_session_auth).post(post_session_auth),
        )
        .route(API_PATH_PAIRING, get(get_pairing).post(post_pairing))
        .route(API_PATH_PAIRING_STATUS, get(get_pairing_status))
        .route(
            API_PATH_SETUP_EASY,
            get(show_network_setup).post(update_network_setup),
        )
        .route(API_PATH_SHOW_EMOJI, get(show_emoji))
        .route(API_PATH_LOGOUT, get(logout))
        .route(API_PATH_SYSTEM_CHECKING, get(system_checking))
        .route(API_PATH_POR_WIFI, get(por_wifi).post(por_wifi))
        .layer(Extension(store))
        .layer(Extension(cache))
        .layer(Extension(Arc::new(otp)))
        /*.merge(axum_extra::routing::SpaRouter::new(
            "/__res__",
            opt.static_dir,
        ))*/;

    let addr = SocketAddr::from((
        IpAddr::from_str(opt.private_addr.as_str()).unwrap_or(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        opt.private_port,
    ));

    match (opt.certificate, opt.private_key) {
        (Some(ref cert), Some(ref pkey)) => {
            let config = RustlsConfig::from_pem_file(cert, pkey).await.unwrap();

            tracing::info!("listening on https://{} for private", addr);

            axum_server::bind_rustls(addr, config)
                .serve(app.into_make_service())
                .await
                .unwrap();
        }
        (_, _) => {
            tracing::info!("listening on http://{} for private", addr);
            axum::Server::bind(&addr)
                .serve(app.into_make_service())
                .await
                .unwrap();
        }
    }
}

async fn public_service(
    public_addr: String,
    public_port: u16,
    redis_addr: String,
    mut wallet: Option<String>,
    cert: Option<String>,
    private_key: Option<String>,
) {
    let redis_addr = format!("redis://{}/", redis_addr);
    let cache = redis::Client::open(redis_addr).unwrap();

    if let Ok(mut db_conn) = cache.get_async_connection().await {
        let value = db_conn
            .get::<&str, String>("kap.core")
            .await
            .or(Err("kap.core not found"))
            .and_then(|s| serde_json::from_str::<CoreMenu>(&s).or(Err("json convert fail")));
        if let Ok(value) = value {
            wallet = wallet.or(Some(value.wallet_address));
        }
    }

    let app = Router::new()
        .route(
            API_PATH_HONEST_CHALLENGE,
            get(honest_challenge).post(update_honest_challenge),
        )
        .route(API_PATH_OPENNDS_FAS, get(public_opennds_fas))
        .layer(Extension(cache))
        .layer(Extension(wallet.unwrap()))
        .into_make_service_with_connect_info::<SocketAddr>();

    let addr = SocketAddr::from((
        IpAddr::from_str(&public_addr).unwrap_or(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        public_port,
    ));

    match (cert, private_key) {
        (Some(ref cert), Some(ref pkey)) => {
            let config = RustlsConfig::from_pem_file(cert, pkey).await.unwrap();

            tracing::info!("listening on https://{} for public", addr);

            axum_server::bind_rustls(addr, config)
                .serve(app)
                .await
                .unwrap();
        }
        (_, _) => {
            tracing::info!("listening on http://{} for public", addr);

            axum::Server::bind(&addr).serve(app).await.unwrap();
        }
    }
}

async fn logout(
    Extension(store): Extension<MemoryStore>,
    cookies: Option<TypedHeader<headers::Cookie>>,
) -> impl IntoResponse {
    if let Some(TypedHeader(cookies)) = cookies {
        let cookie = cookies.get(COOKIE_NAME).unwrap();
        let session = match store.load_session(cookie.to_string()).await.unwrap() {
            Some(s) => s,
            // No session active, just redirect
            None => return Redirect::to("/"),
        };

        store.destroy_session(session).await.unwrap();
    }

    Redirect::to("/")
}

async fn index(
    user: Option<SessionUser>,
    Extension(server_ctx): Extension<Arc<ServerCtx>>,
) -> impl IntoResponse {
    if server_ctx.need_login(user).is_err() {
        return Redirect::temporary(API_PATH_AUTH_SIMPLE).into_response();
    }

    match online::check(Some(3)).await {
        Ok(c) => {
            debug!("online check ok - {:?}", c);
            Redirect::temporary(API_PATH_PAIRING).into_response()
        },
        Err(e) => {
            debug!("online check err - {:?}", e);
            Redirect::temporary(API_PATH_SETUP_EASY).into_response()
        },
    }
}

async fn get_session_auth() -> Html<&'static str> {
    Html(std::include_str!("../templates/login.html"))
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
struct SessionUser {
    name: String,
    password: String,
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

async fn post_session_auth(
    input: JsonOrForm<SessionUser>,
    Extension(server_ctx): Extension<Arc<ServerCtx>>,
    Extension(store): Extension<MemoryStore>,
) -> impl IntoResponse {
    //dbg!(&server_ctx);
    //debug!("[post-session-auth] login {:?}", &input);

    let mut headers = HeaderMap::new();

    let (is_json, login) = match input {
        JsonOrForm::Json(j) => (true, j),
        JsonOrForm::Form(f) => (false, f),
    };

    if server_ctx.do_login(&login.name, &login.password).is_err() {
        return match is_json {
            false => (headers, Redirect::to(API_PATH_AUTH_SIMPLE)).into_response(),
            true => {
                let resp = json!({"code": 401, "message": "Unauthorized"});
                (StatusCode::UNAUTHORIZED, Json(resp)).into_response()
            },
        }
    }

    // Create a new session filled with user data
    let mut session = Session::new();
    session.insert("user", &login).unwrap();

    // Store session and get corresponding cookie
    let cookie = store.store_session(session).await.unwrap().unwrap();

    // Build the cookie
    let cookie = format!("{}={}; SameSite=Lax; Path=/", COOKIE_NAME, cookie);

    // Set cookie
    headers.insert(SET_COOKIE, cookie.parse().unwrap());

    match is_json {
        false => (headers, Redirect::to(API_PATH_PAIRING)).into_response(),
        true => (headers, Json(json!({"code": 200, "message": "login success"}))).into_response(),
    }
}

#[derive(Debug)]
enum JsonOrForm<T, K = T> {
    Json(T),
    Form(K),
}

#[async_trait]
impl<B, T, U> FromRequest<B> for JsonOrForm<T, U>
where
    B: Send,
    Json<T>: FromRequest<B>,
    Form<U>: FromRequest<B>,
    T: 'static,
    U: 'static,
{
    type Rejection = Response;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let content_type_header = req.headers().get(CONTENT_TYPE);
        let content_type = content_type_header.and_then(|value| value.to_str().ok());

        if let Some(content_type) = content_type {
            if content_type.starts_with("application/json") {
                let Json(payload) = req.extract().await.map_err(IntoResponse::into_response)?;
                return Ok(Self::Json(payload));
            }

            if content_type.starts_with("application/x-www-form-urlencoded") {
                let Form(payload) = req.extract().await.map_err(IntoResponse::into_response)?;
                return Ok(Self::Form(payload));
            }
        }

        Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response())
    }
}

fn check_application_json<B>(req: &RequestParts<B>) -> Result<()> {
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

#[derive(Debug)]
enum AppType {
    Html,
    Json,
}

#[async_trait]
impl<B> FromRequest<B> for AppType
where
    B: Send,
{
    type Rejection = Response;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        check_application_json(req)
            .and_then(|_| Ok(Self::Json))
            .or_else(|_| Ok(Self::Html))
    }
}

const EASY_SETUP_TEMP: &str = std::include_str!("../templates/easy_setup.html");

#[derive(Debug, Serialize, Deserialize, Clone)]
enum WanType {
    Dhcp,
    Pppoe,
    Wwan,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
struct NetworkConfig {
    wan_type: u8,
    wan_username: Option<String>,
    wan_password: Option<String>,
    wifi_ssid: String,
    wifi_password: Option<String>,
    password_overwrite: Option<String>,
}

struct AuthRedirect(bool);

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

async fn show_network_setup(
    user: Option<SessionUser>,
    Extension(cache): Extension<redis::Client>,
    Extension(server): Extension<Arc<ServerCtx>>,
) -> impl IntoResponse {
    if server.need_login(user).is_err() {
        return Redirect::temporary(API_PATH_AUTH_SIMPLE).into_response();
    }

    let mut cfg = String::from(
        r#"{"wan_type":0,"wan_username":"example","wan_password":"example","wifi_ssid":"k-private","wifi_password":"changeme","password_overwrite":"on"}"#,
    );
    if let Ok(mut conn) = cache.get_async_connection().await {
        cfg = conn
            .get::<&str, String>(KEY_KAP_SYSTEM_CONFIG)
            .await
            .unwrap_or_else(|_| "{}".into());
    }
    Html(EASY_SETUP_TEMP.replace("{{ getJson }}", &cfg)).into_response()
}

// Valid user session required. If there is none, redirect to the auth page
async fn update_network_setup(
    user: Option<SessionUser>,
    Form(cfg): Form<NetworkConfig>,
    Extension(cache): Extension<redis::Client>,
    Extension(server_ctx): Extension<Arc<ServerCtx>>,
) -> impl IntoResponse {
    if server_ctx.need_login(user).is_err() {
        return Redirect::temporary(API_PATH_AUTH_SIMPLE).into_response();
    }

    //dbg!(&cfg);
    let ipc_key = KEY_KAP_SYSTEM_CONFIG;

    let msg = match serde_json::to_string(&cfg) {
        Ok(c) => c,
        Err(e) => {
            dbg!(&e);
            "{}".into()
        }
    };

    if let Ok(mut conn) = cache.get_async_connection().await {
        if let Ok(orig) = conn.get::<&str, String>(ipc_key).await {
            if orig != msg {
                let key = format!("{}.old", ipc_key);
                if let Err(e) = conn.set::<&str, &str, String>(&key, &orig).await {
                    error!("ipc backup {:?}/{:?} error - {:?}",
                           key, orig, e);
                }
            } else {
                return get_result_emoji("Setup Done", "rocket").await.into_response();
            }
        }

        conn.set::<&str, &str, String>(ipc_key, &msg)
            .await
            .unwrap();
        conn.publish::<&str, &str, usize>(ipc_key, &msg)
            .await
            .unwrap();

        let mut sub_conn = conn.into_pubsub();
        sub_conn.subscribe(&format!("{ipc_key}.ack")).await.unwrap();
        let mut sub_stream = sub_conn.on_message();

        /*TODO, ui/ux display progress for this long-term job */
        let resp = tokio::select! {
            Some(res) = sub_stream.next() => {
                //res.get_payload::<String>().unwrap(),
                match res.get_payload::<String>() {
                    Ok(_) => {
                        //auth.renew();
                        "rocket".to_string()
                    },
                    _ => "NG".to_string(),
                }
            },
            _ = time::sleep(Duration::from_secs(60)) => "hourglass not done".to_string(),
        };

        get_result_emoji("Setup Done", &resp).await.into_response()
    } else {
        dbg!(&msg);
        let resp = "NG".to_string();
        get_result_emoji("Setup Fail", &resp).await.into_response()
    }
}

const RESULT_TEMP: &str = std::include_str!("../templates/result.html");

async fn get_result_emoji(result: &str, emoji: &str) -> impl IntoResponse {
    match emojis::get_by_shortcode(emoji) {
        Some(image) => {
            //dbg!(image.clone());
            Html(
                RESULT_TEMP
                    .replace("{{ emoji }}", &String::from_utf8_lossy(&image.as_bytes()))
                    .replace("{{ result }}", result),
            )
        }
        None => Html(
            RESULT_TEMP
                .replace("{{ emoji }}", "")
                .replace("{{ result }}", result),
        ),
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[allow(dead_code)]
struct EmojiStr {
    code: String,
}

async fn show_emoji(emoji: Option<Query<EmojiStr>>) -> impl IntoResponse {
    let Query(emoji) = emoji.unwrap_or_default();
    get_result_emoji(&emoji.code, &emoji.code).await
}

const PAIRING_TEMP: &str = std::include_str!("../templates/pairing.html");

#[derive(Debug, Serialize, Deserialize, Clone)]
struct IotPairingCfg {
    //#[serde(rename = "wallet-address")]
    wallet: Option<String>,
    //#[serde(rename = "confirm-otp")]
    otp: Option<String>,
    expire: Option<DateTime<Utc>>,
}

/*mod my_date_format {
    /// ref from https://serde.rs/custom-date-format.html
    use chrono::{DateTime, Local, TimeZone};
    use serde::{self, Deserialize, Deserializer, Serializer};

    const FORMAT: &'static str = "%Y-%m-%d %H:%M:%S";
    pub fn serialize<S>(date: &DateTime<Local>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = format!("{}", date.format(FORMAT));
        serializer.serialize_str(&s)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Local>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Local
            .datetime_from_str(&s, FORMAT)
            .map_err(serde::de::Error::custom)
    }
}*/

#[derive(Debug, Serialize, Deserialize, Clone)]
struct KApOtp {
    otp: String,
    /*#[serde(with = "my_date_format")]
    invalid_time: DateTime<Local>,*/
    invalid_time: DateTime<Utc>,
    code: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct InternalServerCtx {
    otp: String,
    code: u16,
    invalid_time: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ServerCtx {
    api_url: String,
    otp_path: String,
    ap_info_path: String,
    access_token: String,
    access_token_ap: String,
    wallet: String,
    mac: String,

    /* authenticate */
    login_name: Option<String>,
    login_password: Option<String>,

    internal: Mutex<InternalServerCtx>,
}

impl ServerCtx {
    fn new(
        api_url: Option<String>,
        otp_path: Option<String>,
        ap_info_path: Option<String>,
        access_token: Option<String>,
        access_token_ap: Option<String>,
        wallet: Option<String>,
        mac: Option<String>,
        login_name: Option<String>,
        login_password: Option<String>,
    ) -> Self {
        ServerCtx {
            api_url: api_url.map_or("https://oss-api.k36588.info".to_owned(), |v| v),
            access_token: access_token.map_or("ce18d7a0940719a00da82448b38c90b2".to_owned(), |v| v),
            access_token_ap: access_token_ap
                .map_or("02ec7a905b70689d9b30c6118fd1e62f".to_owned(), |v| v),
            otp_path: otp_path.map_or("v0/ap/otp".to_owned(), |v| v),
            ap_info_path: ap_info_path.map_or("v0/ap/info".to_owned(), |v| v),
            wallet: wallet.map_or(
                "5KaELZtvrm7sW4pxkBavKkcX7Mx2j5Zg6W8hYXhzoLxT".to_owned(),
                |v| v,
            ),
            mac: mac.map_or("a1:a2:33:44:55:66".to_string(), |v| v),

            login_name,
            login_password,

            internal: Mutex::new(InternalServerCtx {
                otp: repeat_with(fastrand::alphanumeric).take(6).collect(),
                invalid_time: Utc::now(), /* + chrono::Duration::seconds(300)*/
                code: 404,
            }),
        }
    }

    async fn get_mac_address(&self, skip: usize) -> String {
        let mac: String = self.mac.split(":")
            .skip(skip)
            .map(|m| m.to_uppercase())
            .fold(String::from("-"), |all, m| all + m.as_str());
        mac
    }

    async fn get_boss_otp(&self) -> Result<String> {
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

    async fn db_boss_owner(&self, mut conn: redis::aio::Connection) -> Result<BossApInfoData> {
        /* updted via MQTT/subscribe in fika-manager */
        conn.get::<&str, String>("kap.boss.ap.info")
            .await
            .or(Err(anyhow!("kap.boss.ap.info not found")))
            .and_then(|s| {
                serde_json::from_str::<BossApInfoData>(&s).or(Err(anyhow!("json convert fail")))
            })
    }

    async fn get_boss_owner(&self, conn: Result<redis::aio::Connection>) -> Result<String> {
        /*XXX, just disable until oss->cmp->kap ready
         * if let Ok(conn) = conn {
            if let Ok(info) = self.db_boss_owner(conn).await {
                //return info.user_wallet
                //    .ok_or(anyhow!("user-wallet non-exist"));
                if info.user_wallet.is_some() {
                    return Ok(info.user_wallet.unwrap());
                }
            }
        }*/

        /* trandition BOSS/polling flow */
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
                    Ok(
                        serde_json::from_value::<String>(response["data"]["user_wallet"].take())
                            .unwrap(),
                    )
                } else {
                    Err(anyhow::anyhow!(serde_json::from_value::<String>(
                        response["message"].take()
                    )
                    .unwrap()))
                }
            }
            _ => Err(anyhow::anyhow!("unknown error".to_owned())),
        }
    }

    fn as_app_query(&self, otp: Option<String>) -> Result<KAppOtp> {
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

    fn get_shadow_password(&self, username: &str) -> Result<String> {
        match shadow::Shadow::from_name(username) {
            Some(s) => Ok(s.password),
            None => {
                Err(anyhow::anyhow!("User {} password not found", username))
            },
        }
    }

    fn need_login(&self, user: Option<SessionUser>) -> Result<()> {
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

    fn do_login(&self, user: &str, passwd: &str) -> Result<()> {
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

#[derive(Debug, Serialize, Deserialize, Clone)]
struct KAppOtp {
    ap_wallet: String,
    otp: String,
    url: String,
    //ap_mac: Option<String>, //XXX remove MAC
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[allow(dead_code)]
struct OwnerInfo {
    nickname: String,
}

#[debug_handler]
async fn get_pairing(
    user: Option<SessionUser>,
    app_type: AppType,
    owner_info: Option<Query<OwnerInfo>>,
    Extension(server_ctx): Extension<Arc<ServerCtx>>,
    Extension(cache): Extension<redis::Client>,
) -> impl IntoResponse {
    if server_ctx.need_login(user).is_err() {
        match app_type {
            AppType::Html => return Redirect::temporary(API_PATH_AUTH_SIMPLE).into_response(),
            AppType::Json => {
                let resp = json!({"code": 401, "message": "Unauthorized"});
                return (StatusCode::OK, Json(resp)).into_response();
            }
        }
    }

    let db_conn = cache
        .get_async_connection()
        .await
        .or(Err(anyhow!("db async connect fail")));
    let owner = server_ctx.get_boss_owner(db_conn).await;
    let (owner_id, paired, app_otp) = if owner.is_ok() {
        let otp = KAppOtp {
            ap_wallet: "...".to_string(),
            otp: "...".to_string(),
            url: "...".to_string(),
        };
        (owner.unwrap(), true, otp)
    } else {
        let pincode = server_ctx.get_boss_otp().await.ok();
        let app_otp = server_ctx.as_app_query(pincode).unwrap();

        ("non-exist-owner".to_string(), false, app_otp)
    };

    let conn = cache.get_async_connection().await.or_else(|e| Err(anyhow!("IPC async connect fail - {:?}", e)));
    let por = ipc_get_por_config(conn).await
        .ok()
        .and_then(|p| p.nickname)
        .or(None);

    let nickname = if por.is_none() {
        if let Some(owner_info) = owner_info {
            format!("{}'s K-AP", owner_info.nickname)
        } else {
            let mac = server_ctx.get_mac_address(3).await;
            format!("K-AP{}", mac)
        }
    } else {
        por.unwrap()
    };

    match app_type {
        AppType::Json => {
            let resp = json!({
                "code": 200,
                "ap_wallet": server_ctx.wallet.clone(),
                "otp": if paired == true { "null" } else { &app_otp.otp},
                "nickname": nickname,
                "ownerId": owner_id,
                "paired": paired
            });
            return (StatusCode::OK, Json(resp)).into_response();
        }
        AppType::Html => {
            let owner_json = json!({
                "ownerId": owner_id,
                "nickname": nickname,
                "paired": paired
            });

            let cfg = serde_json::to_string(&app_otp).unwrap();
            let code = QrCode::new(cfg.into_bytes()).unwrap();
            let mut image = code
                .render()
                .min_dimensions(60, 60)
                .max_dimensions(360, 360)
                .light_color(svg::Color("#696969"))
                .dark_color(svg::Color("#fff"))
                .quiet_zone(true)
                .build()
                .into_bytes();
            image.push(b'\n');

            Html(
                PAIRING_TEMP
                    .replace("{{ content }}", &String::from_utf8_lossy(&image))
                    .replace("{{ getJson }}", &owner_json.to_string())
                    .replace("{{ otp }}", &app_otp.otp)
                    .replace("{{ ownerId }}", &owner_id)
                    .replace("{{ routerId }}", &app_otp.ap_wallet),
            )
            .into_response()
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct PairingCfg {
    user_wallet: Option<String>,
    nickname: String,
}

impl PairingCfg {
    fn generate_por_cfg(&self) -> PorCfg {
        PorCfg {
            state: true,
            nickname: Some(self.nickname.clone()),
        }
    }
}

#[debug_handler]
async fn post_pairing(
    user: Option<SessionUser>,
    //app_type: AppType,
    Json(input): Json<PairingCfg>,
    Extension(cache): Extension<redis::Client>,
    Extension(server_ctx): Extension<Arc<ServerCtx>>,
) -> impl IntoResponse {
    if server_ctx.need_login(user).is_err() {
        let resp = json!({"code": 401, "message": "Unauthorized"});
        return (StatusCode::OK, Json(resp)).into_response();
    }

    let ipc_key = KEY_KAP_POR_CONFIG;
    let por = input.generate_por_cfg();
    let msg = serde_json::to_string(&por).unwrap();

    let (code, message) = if let Ok(mut conn) = cache.get_async_connection().await {
        if let Ok(orig) = conn.get::<&str, String>(ipc_key).await {
            if orig != msg {
                let key = format!("{}.old", ipc_key);
                if let Err(e) = conn.set::<&str, &str, String>(&key, &orig).await {
                    error!("ipc backup {:?}/{:?} error - {:?}",
                           key, orig, e);
                }
            } else {
                let resp = json!({"code": 200, "message": "do nothing"});
                return (StatusCode::OK, Json(resp)).into_response();
            }
        }

        match conn
            .set::<&str, &str, String>(ipc_key, &msg)
            .await
        {
            Ok(_) => {}
            Err(_e) => {
                error!("ipc {}/{} set fail", ipc_key, &msg);
            }
        }

        if let Ok(_) = conn
            .publish::<&str, &str, usize>(ipc_key, &msg)
            .await
        {
            let mut sub_conn = conn.into_pubsub();
            sub_conn
                .subscribe(&format!("{}.ack", ipc_key))
                .await
                .unwrap();
            let mut sub_stream = sub_conn.on_message();

            _ = tokio::select! {
                Some(res) = sub_stream.next() => {
                    let r = res.get_payload::<String>();
                    debug!("ipc {} receive ack as {:?}",
                           ipc_key, r);
                },
                _ = time::sleep(Duration::from_secs(60)) => {
                    debug!("ipc {ipc_key} receive ack timeout");
                }
            };
        } else {
            error!("ipc {}/{} pub fail", ipc_key, &msg);
        }
        (200, "success")
    } else {
        (501, "internal server error")
    };

    let resp = json!({"code": code, "message": message});
    return (StatusCode::OK, Json(resp)).into_response();
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PairingStatus {
    code: u16,
    paired: bool,
    owner_wallet: Option<String>,
    ap_wallet: Option<String>,
}

async fn get_pairing_status(
    Extension(cache): Extension<redis::Client>,
    Extension(server_ctx): Extension<Arc<ServerCtx>>,
) -> impl IntoResponse {
    let mut status = PairingStatus {
        code: 200, /* StatusCode::INTERNAL_SERVER_ERROR */
        paired: false,
        owner_wallet: None,
        ap_wallet: Some(server_ctx.wallet.clone()),
    };

    let db_conn = cache
        .get_async_connection()
        .await
        .or(Err(anyhow!("db async connect fail")));
    let owner = server_ctx.get_boss_owner(db_conn).await;
    if owner.is_ok() {
        status.paired = true;
        status.owner_wallet = Some(owner.unwrap());
    }

    (StatusCode::OK, Json(status))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct HonestChallengeResponse {
    code: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct HonestChallengeRequest {
    gw_id: String,
    hashed: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct HonestChallengeContent {
    gw_id: Option<String>,
    token: Option<String>,
    code: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct BossHcsPair {
    hcs_sid: String,
    hcs_token: String,
    init_time: DateTime<Utc>,
    invalid_time: DateTime<Utc>,
}

static KEY_BOSS_HCS_CHALLENGERS: &str = "boss.hcs.challengers";

impl BossHcsPair {
    async fn get(conn: &mut redis::aio::Connection) -> Result<BossHcsPair> {
        let hcs_list = "boss.hcs.token.list";
        if let Ok(token) = conn.lindex::<&str, String>(hcs_list, 0).await {
            debug!("redis {} first ^{}$ success", hcs_list, token);
            if let Ok(boss_hcs) = serde_json::from_str::<BossHcsPair>(&token) {
                let now = Utc::now();
                if now >= boss_hcs.init_time && now < boss_hcs.invalid_time {
                    return Ok(boss_hcs);
                }
            }
        }
        Err(anyhow::anyhow!("HCS task not found"))
    }

    #[cfg(challenge_limit)]
    async fn new_challenge(
        &self,
        conn: &mut redis::aio::Connection,
        challenger_id: &str,
    ) -> Result<()> {
        let key = format!("{}.{}", KEY_BOSS_HCS_CHALLENGERS, self.hcs_token);
        if let Ok(exist) = conn.hexists::<&str, &str, bool>(&key, challenger_id).await {
            if exist {
                return Err(anyhow::anyhow!(
                    "{} have challenged in {} session",
                    challenger_id,
                    self.hcs_sid
                ));
            }
        }

        return Ok(());
    }

    #[cfg(not(challenge_limit))]
    async fn new_challenge(
        &self,
        _conn: &mut redis::aio::Connection,
        _challenger_id: &str,
    ) -> Result<()> {
        Ok(())
    }

    async fn push_server(
        &self,
        conn: &mut redis::aio::Connection,
        challenger_id: &str,
        hashed: &str,
    ) -> Result<()> {
        let value = serde_json::json!({
            "hashed": hashed,
            "sent": false
        });
        let key = format!("{}.{}", KEY_BOSS_HCS_CHALLENGERS, self.hcs_token);
        let _ = conn
            .hset::<&str, &str, &str, _>(&key, challenger_id, &value.to_string())
            .await?;

        let notify = "boss.honest.challenger";
        let _ = conn.publish::<&str, &str, _>(notify, challenger_id).await?;
        Ok(())
    }
}

async fn honest_challenge(
    Path(challenger_id): Path<String>,
    Extension(cache): Extension<redis::Client>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(wallet): Extension<String>,
) -> impl IntoResponse {
    info!("client ip-address {}", addr);

    let mut challenge = HonestChallengeContent {
        gw_id: None,
        token: None,
        code: 404, // not-found
    };

    if let Ok(mut conn) = cache.get_async_connection().await {
        match BossHcsPair::get(&mut conn).await {
            Ok(hcs) => {
                if hcs.new_challenge(&mut conn, &challenger_id).await.is_ok() {
                    challenge.token = Some(hcs.hcs_token);
                    challenge.gw_id = Some(wallet.clone());
                    challenge.code = 200;
                } else {
                    debug!("{} has challenged in this task", &challenger_id);
                    challenge.code = 406;
                }
            }
            Err(_) => {
                debug!("No challenge task");
                challenge.code = 404;
            }
        }
    } else {
        debug!("internal DB server error");
    }

    (StatusCode::OK, Json(challenge))
}

async fn update_honest_challenge(
    Path(challenger_id): Path<String>,
    Json(hc_request): Json<HonestChallengeRequest>,
    Extension(cache): Extension<redis::Client>,
    Extension(wallet): Extension<String>,
) -> impl IntoResponse {
    let mut resp = HonestChallengeResponse {
        code: 404, // not-found
    };

    if &hc_request.gw_id != &wallet {
        resp.code = 405; //METHOD_NOT_ALLOWED;
        return (StatusCode::OK, Json(resp));
    }

    if hc_request.hashed.len() > 128 {
        resp.code = 400; //BAD_REQUEST due to length overflow
        return (StatusCode::OK, Json(resp));
    }

    if let Ok(mut conn) = cache.get_async_connection().await {
        match BossHcsPair::get(&mut conn).await {
            Ok(hcs) => {
                if hcs.new_challenge(&mut conn, &challenger_id).await.is_ok() {
                    if hcs
                        .push_server(&mut conn, &challenger_id, &hc_request.hashed)
                        .await
                        .is_ok()
                    {
                        resp.code = 200;
                    } else {
                        debug!("{} push srever error", &challenger_id);
                        resp.code = 502; //BAD_GATEWAY
                    }
                } else {
                    debug!("{} has challenged in this task", &challenger_id);
                    resp.code = 406;
                }
            }
            Err(_) => {
                debug!("No challenge task");
                resp.code = 404;
            }
        }
    } else {
        resp.code = 500; //StatusCode::INTERNAL_SERVER_ERROR
    }
    (StatusCode::OK, Json(resp))
}

/*#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
struct SimpleAuth {
    name: String,
    password: Mutex<Option<String>>,
}

impl SimpleAuth {
    fn new(username: Option<String>, password: Option<String>) -> Self {
        let name = match username {
            Some(u) => u,
            None => env::var("CLIENT_ID").unwrap_or("admin".to_string()),
        };
        let password = match password {
            Some(p) => p,
            None => match env::var("CLIENT_SECRET") {
                Ok(p) => p,
                Err(_) => match shadow::Shadow::from_name(&name) {
                    Some(s) => s.password,
                    None => String::from(""),
                },
            },
        };
        SimpleAuth {
            name,
            password: Mutex::new(Some(password)),
        }
    }

    fn renew(&self) {
        let password = match shadow::Shadow::from_name(&self.name) {
            Some(s) => s.password,
            None => String::from(""),
        };
        self.password.lock().unwrap().replace(password);
    }

    fn get_password(&self) -> Option<String> {
        match self.password.lock() {
            Ok(p) => match &*p {
                Some(p) => Some(p.clone()),
                None => None,
            },
            Err(_) => None,
        }
    }
}*/

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(dead_code)]
struct SystemChecking {
    code: u16,
    message: String,
}

async fn system_checking(
    user: Option<SessionUser>,
    Extension(cache): Extension<redis::Client>,
    Extension(server_ctx): Extension<Arc<ServerCtx>>,
) -> impl IntoResponse {
    if server_ctx.need_login(user).is_err() {
        return Redirect::temporary(API_PATH_AUTH_SIMPLE).into_response();
    }

    let mut emoji = String::from("prohibited");
    if let Ok(mut conn) = cache.get_async_connection().await {
        match conn.get::<&str, String>("kdaemon.system.checking").await {
            Ok(data) => {
                if let Ok(sc) = serde_json::from_str::<SystemChecking>(&data) {
                    if sc.code == 200 {
                        emoji = "rocket".to_string();
                    }
                }
            }
            Err(_) => {}
        }
    }
    get_result_emoji("System Check...", &emoji)
        .await
        .into_response()
}

const POR_TEMP: &str = std::include_str!("../templates/por.html");

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct PorCfg {
    state: bool,
    nickname: Option<String>,
}

async fn _por_config(
    user: Option<SessionUser>,
    Extension(cache): Extension<redis::Client>,
) -> impl IntoResponse {
    if user.is_none() {
        Redirect::temporary(API_PATH_AUTH_SIMPLE).into_response()
    } else {
        let mut cfg = String::from("{}");
        if let Ok(mut conn) = cache.get_async_connection().await {
            cfg = conn
                .get::<&str, String>(KEY_KAP_POR_CONFIG)
                .await
                .unwrap_or_else(|_| "{}".into());
        }
        Html(POR_TEMP.replace("{{ getJSON }}", &cfg)).into_response()
    }
}

static KEY_KAP_POR_CONFIG: &str = "kap.por.config";
static KEY_KAP_SYSTEM_CONFIG: &str = "kdaemon.easy.setup";

async fn ipc_get_por_config(ipc: Result<redis::aio::Connection>) -> Result<PorCfg> {
    let cfg = if let Ok(mut conn) = ipc {
        conn.get::<&str, String>(KEY_KAP_POR_CONFIG)
            .await
            .unwrap_or_else(|_| r#"{"state":true,"nickname":null}"#.to_string())
    } else {
        r#"{"state":true,"nickname":null}"#.to_string()
    };
    serde_json::from_str::<PorCfg>(&cfg).or_else(|e| Err(anyhow!("serde error {:?}", e)))
}

// Valid user session required. If there is none, redirect to the auth page
async fn por_wifi(
    user: Option<SessionUser>,
    payload: Option<Json<PorCfg>>,
    Extension(cache): Extension<redis::Client>,
    Extension(server_ctx): Extension<Arc<ServerCtx>>,
) -> impl IntoResponse {
    if server_ctx.need_login(user).is_err() {
        return Redirect::temporary(API_PATH_AUTH_SIMPLE).into_response();
    }

    //dbg!(&payload);
    let ipc_key = KEY_KAP_POR_CONFIG;

    if let Some(Json(input)) = payload {
        let msg = serde_json::to_string(&input).unwrap();
        let mut resp = "thumbs down".to_string();

        if let Ok(mut conn) = cache.get_async_connection().await {
            if let Ok(orig) = conn.get::<&str, String>(ipc_key).await {
                if orig != msg {
                    let key = format!("{}.old", ipc_key);
                    if let Err(e) = conn.set::<&str, &str, String>(&key, &orig).await {
                        error!("ipc backup {:?}/{:?} error - {:?}",
                               key, orig, e);
                    }
                } else {
                    return get_result_emoji("PoR service", "rocket").await.into_response()
                }
            }

            match conn
                .set::<&str, &str, String>(ipc_key, &msg)
                .await
            {
                Ok(_) => {}
                Err(_e) => {
                    error!("ipc {}/{} set fail", ipc_key, &msg);
                }
            }

            if let Ok(_) = conn
                .publish::<&str, &str, usize>(ipc_key, &msg)
                .await
            {
                let mut sub_conn = conn.into_pubsub();
                sub_conn
                    .subscribe(&format!("{}.ack", ipc_key))
                    .await
                    .unwrap();
                let mut sub_stream = sub_conn.on_message();

                resp = tokio::select! {
                    Some(res) = sub_stream.next() => {
                        match res.get_payload::<String>() {
                            Ok(status) => {
                                if status.eq("success") {
                                    "rocket".to_string()
                                }
                                else {
                                    "thumbs down".to_string()
                                }
                            },
                            _ => "pick".to_string(),
                        }
                    },
                    _ = time::sleep(Duration::from_secs(60)) => "hourglass not done".to_string(),
                };
            } else {
                error!("ipc {}/{} pub fail", ipc_key, &msg);
            }
        } else {
            error!("ipc async connect fail");
        }

        get_result_emoji("PoR service", &resp).await.into_response()
    } else {
        /*let cfg = if let Ok(mut conn) = cache.get_async_connection().await {
            conn.get::<&str, String>(KEY_KAP_POR_CONFIG)
                .await
                .unwrap_or_else(|_| r#"{"state":true,"nickname":"null"}"#.to_string())
        } else {
            r#"{"state":true,"nickname":"null"}"#.to_string()
        };*/

        let conn = cache.get_async_connection().await.or_else(|e| Err(anyhow!("IPC async connect fail - {:?}", e)));
        let cfg = ipc_get_por_config(conn)
            .await
            .and_then(|c| serde_json::to_string(&c)
                      .or_else(|e| Err(anyhow!("serde to string fail - {:?}", e)))
          ).unwrap();

        Html(POR_TEMP.replace("{{ getJson }}", &cfg)).into_response()
    }
}

const FAS_TEMP: &str = std::include_str!("../templates/opennds_fas.html");
async fn public_opennds_fas(
    req: Option<Query<String>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    dbg!(req);
    dbg!(addr);

    Html(FAS_TEMP).into_response()
}
