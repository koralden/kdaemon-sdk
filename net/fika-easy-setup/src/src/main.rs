//! Ref axum/example/OAuth (Discord) implementation.
//!
//! 1) Create a new application at <https://discord.com/developers/applications>
//! 2) Visit the OAuth2 tab to get your CLIENT_ID and CLIENT_SECRET
//! 3) Add a new redirect URI (for this example: `http://127.0.0.1:3000/auth/authorized`)
//! 4) Run with the following (replacing values appropriately):
//! ```not_rust
//! CLIENT_ID=REPLACE_ME CLIENT_SECRET=REPLACE_ME cargo run -p example-oauth
//! ```

use anyhow::Result;
use async_session::{MemoryStore, Session, SessionStore};
use axum::{
    async_trait,
    extract::Form,
    extract::{
        rejection::TypedHeaderRejectionReason, Extension, FromRequest, Query, RequestParts,
        TypedHeader,
    },
    http::{header::SET_COOKIE, HeaderMap, StatusCode},
    response::Html,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use futures_util::StreamExt as _;
use http::header;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use qrcode::render::svg;
use qrcode::QrCode;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;
use std::{env, net::SocketAddr};
use tokio::time::{self, Duration};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug, Clone)]
#[clap(
    name = "fika-easy-setup",
    about = "FIKA easy setup server for pairing, challenge and  easy setup"
)]
struct Opt {
    /// set the listen addr
    #[clap(short = 'a', long = "addr", default_value = "::1")]
    addr: String,

    /// set the listen port
    #[clap(short = 'p', long = "port", default_value = "8888")]
    port: u16,

    #[clap(long = "log-level", default_value = "info")]
    log_level: String,

    #[clap(short = 'r', long = "redis", default_value = "127.0.0.1:6379")]
    redis_addr: String,

    #[clap(long = "username", default_value = "tester")]
    client_username: String,

    #[clap(long = "password", default_value = "tester")]
    client_password: String,

    #[clap(
        short = 'w',
        long = "wallet",
        default_value = "5KaELZtvrm7sW4pxkBavKkcX7Mx2j5Zg6W8hYXhzoLxT"
    )]
    wallet_addr: String,

    #[clap(long = "static-dir", default_value = "../templates")]
    static_dir: String,

    #[clap(long = "certificate", default_value = "certs/cert.pem")]
    certificate: String,
    #[clap(long = "private-key", default_value = "certs/key.pem")]
    private_key: String,
}

static COOKIE_NAME: &str = "SESSION";

static API_PATH_SETUP_EASY: &str = "/setup/easy";
static API_PATH_AUTH_SIMPLE: &str = "/auth/simple";
static API_PATH_PAIRING: &str = "/pairing";
static API_PATH_HONEST_CHALLENGE: &str = "/honest/challenge";
static API_PATH_SHOW_EMOJI: &str = "/show/emoji";
static API_PATH_LOGOUT: &str = "/logout";
static API_PATH_SYSTEM_CHECKING: &str = "/system/checking";

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

    // `MemoryStore` is just used as an example. Don't use this in production.
    let store = MemoryStore::new();

    let redis_addr = format!("redis://{}/", opt.redis_addr);
    let cache = redis::Client::open(redis_addr).unwrap();
    //let oauth_client = oauth_client();
    let simple_client = simple_client(&opt);

    let app = Router::new()
        .route("/", get(index))
        //.route("/auth/discord", get(discord_auth))
        //.route("/auth/authorized", get(login_authorized))
        //.route("/protected", get(protected))
        /*.layer(Extension(oauth_client))*/
        .route(
            API_PATH_AUTH_SIMPLE,
            get(show_simple_auth).post(do_simple_auth),
        )
        .route(API_PATH_PAIRING, get(show_pairing).post(create_pairing))
        .route(
            API_PATH_SETUP_EASY,
            get(show_easy_setup).post(update_easy_setup),
        )
        .route(API_PATH_SHOW_EMOJI, get(show_emoji))
        .route(
            API_PATH_HONEST_CHALLENGE,
            get(honest_challenge).post(update_honest_challenge),
        )
        .route(API_PATH_LOGOUT, get(logout))
        .route(API_PATH_SYSTEM_CHECKING, get(system_checking))
        .layer(Extension(store))
        .layer(Extension(cache))
        .layer(Extension(simple_client))
        .layer(Extension(opt.clone()))
        .merge(axum_extra::routing::SpaRouter::new(
            "/__res__",
            opt.static_dir,
        ));

    let addr = SocketAddr::from((
        IpAddr::from_str(opt.addr.as_str()).unwrap_or(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        opt.port,
    ));
    tracing::info!("listening on {}", addr);

    let config = RustlsConfig::from_pem_file(&opt.certificate, &opt.private_key)
        .await
        .unwrap();

    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

fn _oauth_client() -> BasicClient {
    // Environment variables (* = required):
    // *"CLIENT_ID"     "REPLACE_ME";
    // *"CLIENT_SECRET" "REPLACE_ME";
    //  "REDIRECT_URL"  "http://127.0.0.1:3000/auth/authorized";
    //  "AUTH_URL"      "https://discord.com/api/oauth2/authorize?response_type=code";
    //  "TOKEN_URL"     "https://discord.com/api/oauth2/token";

    let client_id = env::var("CLIENT_ID").expect("Missing CLIENT_ID!");
    let client_secret = env::var("CLIENT_SECRET").expect("Missing CLIENT_SECRET!");
    let redirect_url = env::var("REDIRECT_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:3000/auth/authorized".to_string());

    let auth_url = env::var("AUTH_URL").unwrap_or_else(|_| {
        "https://discord.com/api/oauth2/authorize?response_type=code".to_string()
    });

    let token_url = env::var("TOKEN_URL")
        .unwrap_or_else(|_| "https://discord.com/api/oauth2/token".to_string());

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new(auth_url).unwrap(),
        Some(TokenUrl::new(token_url).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap())
}

// The user data we'll get back from Discord.
// https://discord.com/developers/docs/resources/user#user-object-user-structure
#[derive(Debug, Serialize, Deserialize)]
struct DiscordUser {
    id: String,
    avatar: Option<String>,
    username: String,
    discriminator: String,
}

// Session is optional
async fn _index(user: Option<DiscordUser>) -> impl IntoResponse {
    match user {
        Some(u) => format!(
            "Hey {}! You're logged in!\nYou may now access `/protected`.\nLog out with `/logout`.",
            u.username
        ),
        None => "You're not logged in.\nVisit `/auth/discord` to do so.".to_string(),
    }
}

async fn _discord_auth(Extension(client): Extension<BasicClient>) -> impl IntoResponse {
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".to_string()))
        .url();

    // Redirect to Discord's oauth service
    Redirect::to(&auth_url.to_string())
}

// Valid user session required. If there is none, redirect to the auth page
async fn _protected(user: DiscordUser) -> impl IntoResponse {
    format!(
        "Welcome to the protected area :)\nHere's your info:\n{:?}",
        user
    )
}

async fn logout(
    Extension(store): Extension<MemoryStore>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> impl IntoResponse {
    let cookie = cookies.get(COOKIE_NAME).unwrap();
    let session = match store.load_session(cookie.to_string()).await.unwrap() {
        Some(s) => s,
        // No session active, just redirect
        None => return Redirect::to("/"),
    };

    store.destroy_session(session).await.unwrap();

    Redirect::to("/")
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AuthRequest {
    code: String,
    state: String,
}

async fn _login_authorized(
    Query(query): Query<AuthRequest>,
    Extension(store): Extension<MemoryStore>,
    Extension(oauth_client): Extension<BasicClient>,
) -> impl IntoResponse {
    // Get an auth token
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await
        .unwrap();

    // Fetch user data from discord
    let client = reqwest::Client::new();
    let user_data: DiscordUser = client
        // https://discord.com/developers/docs/resources/user#get-current-user
        .get("https://discordapp.com/api/users/@me")
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .unwrap()
        .json::<DiscordUser>()
        .await
        .unwrap();

    // Create a new session filled with user data
    let mut session = Session::new();
    session.insert("user", &user_data).unwrap();

    // Store session and get corresponding cookie
    let cookie = store.store_session(session).await.unwrap().unwrap();

    // Build the cookie
    let cookie = format!("{}={}; SameSite=Lax; Path=/", COOKIE_NAME, cookie);

    // Set cookie
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().unwrap());

    (headers, Redirect::to("/"))
}

struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::temporary("/auth/discord").into_response()
    }
}

#[async_trait]
impl<B> FromRequest<B> for DiscordUser
where
    B: Send,
{
    // If anything goes wrong or no session is found, redirect to the auth page
    type Rejection = AuthRedirect;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(store) = Extension::<MemoryStore>::from_request(req)
            .await
            .expect("`MemoryStore` extension is missing");

        let cookies = TypedHeader::<headers::Cookie>::from_request(req)
            .await
            .map_err(|e| match *e.name() {
                header::COOKIE => match e.reason() {
                    TypedHeaderRejectionReason::Missing => AuthRedirect,
                    _ => panic!("unexpected error getting Cookie header(s): {}", e),
                },
                _ => panic!("unexpected error getting cookies: {}", e),
            })?;
        let session_cookie = cookies.get(COOKIE_NAME).ok_or(AuthRedirect)?;

        let session = store
            .load_session(session_cookie.to_string())
            .await
            .unwrap()
            .ok_or(AuthRedirect)?;

        let user = session.get::<DiscordUser>("user").ok_or(AuthRedirect)?;

        Ok(user)
    }
}

// Session is optional
async fn index(user: Option<SimpleUser>) -> impl IntoResponse {
    match user {
        Some(_u) => Redirect::temporary(API_PATH_SETUP_EASY).into_response(),
        None => Redirect::temporary(API_PATH_AUTH_SIMPLE).into_response(),
    }
}

async fn show_simple_auth() -> Html<&'static str> {
    Html(std::include_str!("../templates/login.html"))
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
struct SimpleUser {
    name: String,
    password: String,
}

#[async_trait]
impl<B> FromRequest<B> for SimpleUser
where
    B: Send,
{
    // If anything goes wrong or no session is found, redirect to the auth page
    type Rejection = AuthRedirect;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(store) = Extension::<MemoryStore>::from_request(req)
            .await
            .expect("`MemoryStore` extension is missing");

        let cookies = TypedHeader::<headers::Cookie>::from_request(req)
            .await
            .map_err(|e| match *e.name() {
                header::COOKIE => match e.reason() {
                    TypedHeaderRejectionReason::Missing => AuthRedirect,
                    _ => panic!("unexpected error getting Cookie header(s): {}", e),
                },
                _ => panic!("unexpected error getting cookies: {}", e),
            })?;
        let session_cookie = cookies.get(COOKIE_NAME).ok_or(AuthRedirect)?;

        let session = store
            .load_session(session_cookie.to_string())
            .await
            .unwrap()
            .ok_or(AuthRedirect)?;

        let user = session.get::<SimpleUser>("user").ok_or(AuthRedirect)?;

        Ok(user)
    }
}

async fn do_simple_auth(
    Form(user): Form<SimpleUser>,
    Extension(client): Extension<SimpleClient>,
    Extension(store): Extension<MemoryStore>,
) -> impl IntoResponse /*Html<&'static str>*/ {
    dbg!(&user);

    let mut headers = HeaderMap::new();

    if user.name == client.name && user.password == client.password {
        // Create a new session filled with user data
        let mut session = Session::new();
        session.insert("user", &user).unwrap();

        // Store session and get corresponding cookie
        let cookie = store.store_session(session).await.unwrap().unwrap();

        // Build the cookie
        let cookie = format!("{}={}; SameSite=Lax; Path=/", COOKIE_NAME, cookie);

        // Set cookie
        headers.insert(SET_COOKIE, cookie.parse().unwrap());

        (headers, Redirect::to(API_PATH_SETUP_EASY))

        //Html(std::include_str!("../templates/easy_setup.html"))
        //Redirect::temporary(API_PATH_SETUP_EASY).into_response()
    } else {
        //Html(std::include_str!("../templates/login.html"))
        //Redirect::temporary("/auth/basic").into_response()
        (headers, Redirect::to(API_PATH_AUTH_SIMPLE))
    }
}

async fn show_easy_setup(user: Option<SimpleUser>) -> Html<&'static str> {
    if user.is_none() {
        //Redirect::temporary(API_PATH_SETUP_EASY).into_response()
        Html(std::include_str!("../templates/login.html"))
    } else {
        Html(std::include_str!("../templates/easy_setup.html"))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
enum WanType {
    Dhcp,
    Pppoe,
    Wwan,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
struct SimpleConfig {
    user_password: Option<String>,
    wan_type: WanType,
    wan_username: Option<String>,
    wan_password: Option<String>,
    wifi_ssid: String,
    wifi_password: Option<String>,
}

// Valid user session required. If there is none, redirect to the auth page
async fn update_easy_setup(
    user: Option<SimpleUser>,
    Form(cfg): Form<SimpleConfig>,
    Extension(cache): Extension<redis::Client>,
) -> impl IntoResponse {
    if user.is_none() {
        Redirect::temporary(API_PATH_AUTH_SIMPLE).into_response()
    } else {
        dbg!(&cfg);

        let mut conn = cache.get_async_connection().await.unwrap();
        let msg = serde_json::to_string(&cfg).unwrap();
        conn.publish::<&str, &str, usize>("kcom:easy:setup", &msg)
            .await
            .unwrap();

        let mut sub_conn = conn.into_pubsub();
        sub_conn.subscribe("platform:easy:setup").await.unwrap();
        let mut sub_stream = sub_conn.on_message();

        /*TODO, ui/ux display progress for this long-term job */
        let resp = tokio::select! {
            Some(res) = sub_stream.next() => {
                //res.get_payload::<String>().unwrap(),
                match res.get_payload::<String>() {
                    Ok(_) => "hundred points".to_string(),
                    _ => "NG".to_string(),
                }
            },
            _ = time::sleep(Duration::from_secs(10)) => "hourglass not done".to_string(),
        };

        get_result_emoji("Setup Done", &resp).await.into_response()
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

async fn show_pairing(
    user: Option<SimpleUser>,
    Extension(opt): Extension<Opt>,
) -> impl IntoResponse {
    if user.is_none() {
        Redirect::temporary(API_PATH_AUTH_SIMPLE).into_response()
    } else {
        let wallet_addr = opt.wallet_addr;

        let code = QrCode::new(wallet_addr.into_bytes()).unwrap();
        let mut image = code
            .render()
            .min_dimensions(360, 360)
            .max_dimensions(360, 360)
            .light_color(svg::Color("#fff"))
            .dark_color(svg::Color("#000"))
            .quiet_zone(true)
            .build()
            .into_bytes();
        image.push(b'\n');

        Html(
            PAIRING_TEMP
                .replace("{{ content }}", &String::from_utf8_lossy(&image))
                .replace("{{ help }}", ""),
        )
        .into_response()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PairingCfg {
    otp: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct IotPairingCfg {
    #[serde(rename = "wallet-address")]
    wallet: String,
    #[serde(rename = "confirm-otp")]
    otp: u16,
}

// Valid user session required. If there is none, redirect to the auth page
async fn create_pairing(
    user: Option<SimpleUser>,
    Json(input): Json<PairingCfg>,
    Extension(cache): Extension<redis::Client>,
    Extension(opt): Extension<Opt>,
) -> impl IntoResponse {
    if user.is_none() {
        Redirect::temporary(API_PATH_AUTH_SIMPLE).into_response()
    } else {
        dbg!(&input);
        let mut conn = cache.get_async_connection().await.unwrap();

        /* input.otp need check or frondend check? */
        if let Ok(otp) = input.otp.parse::<u16>() {
            /* check if have got otp from nms(<-cmp) */
            if let Ok(saved_otp) = conn.get::<&str, u16>("nms.pairing.otp").await {
                if saved_otp == otp {
                    return get_result_emoji("Pairing Fail due to invalid OTP", "broken heart")
                        .await
                        .into_response();
                }
            }

            let iot = IotPairingCfg {
                wallet: opt.wallet_addr,
                otp,
            };

            let msg = serde_json::to_string(&iot).unwrap();
            conn.publish::<&str, &str, usize>("nms.shadow.update.pairing", &msg)
                .await
                .unwrap();

            let mut sub_conn = conn.into_pubsub();
            sub_conn.subscribe("nms.pairing.status").await.unwrap();
            let mut sub_stream = sub_conn.on_message();

            /*TODO, ui/ux display progress for this long-term job */
            let resp = tokio::select! {
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
                _ = time::sleep(Duration::from_secs(10)) => "hourglass not done".to_string(),
            };

            get_result_emoji(&format!("Pairing {}", resp), &resp)
                .await
                .into_response()
        } else {
            get_result_emoji("Pairing Fail due to invalid OTP", "broken heart")
                .await
                .into_response()
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
enum Command {
    Init,
    Hashed,
    Completed,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct HonestChallenge {
    command: Option<Command>,
    token: String,
    hashed: Option<String>,
}

async fn honest_challenge(Extension(cache): Extension<redis::Client>) -> impl IntoResponse {
    let mut conn = cache.get_async_connection().await.unwrap();
    let token: String = conn
        .get("honest:challenge:token")
        .await
        .unwrap_or("TODO: get from redis/subscribe".to_string());

    let challenge = HonestChallenge {
        command: Some(Command::Init),
        token,
        hashed: None,
    };
    (StatusCode::OK, Json(challenge))
}

async fn post_honest_challenge(
    challenge: &mut HonestChallenge,
    mut conn: redis::aio::Connection,
) -> Result<HonestChallenge> {
    let hashed = challenge.hashed.take().unwrap_or("nonexist".to_string());
    let _ = conn
        .set::<&str, &str, usize>("honest:challenge:hashed", &hashed)
        .await?;
    let _ = conn
        .publish::<&str, &str, usize>("honest:challenge:hashed", &hashed)
        .await?;

    /*let pubsub_conn = conn.into_pubsub();
    pubsub_conn.publish("honest:challenge:hashed", &hashed).await?;*/

    /*redis::cmd("SET")
    .arg(&["key2", "bar"])
    .query_async(&mut conn)
    .await.unwrap();*/
    /*let cache = redis::Client::open("redis://127.0.0.1/").unwrap();
    let mut conn = cache.get_async_connection().await.unwrap();
    conn.set::<&str, &str, usize>("honest:challenge:token", "test").await;*/

    /* send to backend and tried to get response */
    let mut response = challenge.clone();
    response.command = Some(Command::Completed);

    Ok(response)
}

async fn update_honest_challenge(
    Json(mut challenge): Json<HonestChallenge>,
    Extension(cache): Extension<redis::Client>,
) -> impl IntoResponse {
    if let Some(ref _hashed) = challenge.hashed {
        if let Ok(conn) = cache.get_async_connection().await {
            if let Ok(resp) = post_honest_challenge(&mut challenge, conn).await {
                (StatusCode::OK, Json(resp))
            } else {
                (StatusCode::NOT_FOUND, Json(challenge))
            }
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(challenge))
        }
    } else {
        (StatusCode::NOT_FOUND, Json(challenge))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(dead_code)]
struct SimpleClient {
    name: String,
    password: String,
}

impl SimpleClient {
    fn new(name: String, password: String) -> Self {
        SimpleClient { name, password }
    }
}

fn simple_client(opt: &Opt) -> SimpleClient {
    let client_username = opt.client_username.clone();
    let client_username = env::var("CLIENT_ID").unwrap_or(client_username);
    let client_password = opt.client_password.clone();
    let client_password = env::var("CLIENT_SECRET").unwrap_or(client_password);

    SimpleClient::new(client_username, client_password)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(dead_code)]
struct SystemChecking {
    code: u16,
    message: String,
}

async fn system_checking(
    user: Option<SimpleUser>,
    Extension(cache): Extension<redis::Client>,
) -> impl IntoResponse {
    if user.is_none() {
        //Redirect::temporary(API_PATH_SETUP_EASY).into_response()
        Redirect::temporary(API_PATH_AUTH_SIMPLE).into_response()
    } else {
        let mut emoji = String::from("prohibited");
        if let Ok(mut conn) = cache.get_async_connection().await {
            match conn.get::<&str, String>("kdaemon.system.checking").await {
                Ok(data) => {
                    if let Ok(sc) = serde_json::from_str::<SystemChecking>(&data) {
                        if sc.code == 200 {
                            emoji = "rocket".to_string();
                        }
                    }
                },
                Err(_) => {},
            }
        }
        get_result_emoji("System Check...", &emoji).await.into_response()
    }
}
