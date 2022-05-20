use serde::{Deserialize, Serialize};
//use redis::AsyncCommands;
use anyhow::Result;
use axum::{
    extract::{ConnectInfo, Extension, Query},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, get_service},
    Router,
};
use chrono::prelude::*;
use redis::Commands;
use redis::{Client, Connection};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing::{debug, error, info};

#[derive(Clone)]
struct FasServCtx {
    db: Arc<Mutex<Connection>>,
    fas_key: String,
    auth_dir: String,
}

impl FasServCtx {
    fn new(db_addr: String, fas_key: String, auth_dir: String) -> Self {
        let db = format!("redis://{}/", db_addr);
        let db = Arc::new(Mutex::new(
            Client::open(db).unwrap().get_connection().unwrap(),
        ));

        Self {
            db,
            fas_key,
            auth_dir,
        }
    }

    fn client_track(&self, params: &QueryParams) -> Result<()> {
        let key = format!("kap.portal.client.{}", params.clientip);
        let value = json!({
            "client-mac": &params.clientmac,
            "onboard-time": Utc::now(),
        })
        .to_string();
        let expire = 12 * 60 * 60;

        if let Ok(mut db) = self.db.lock() {
            if expire == 0 {
                let _ = db.set::<&str, &str, String>(&key, &value);
            } else {
                let _ = db.set_ex::<&str, &str, String>(&key, &value, expire);
            }
        }
        Ok(())
    }
}

pub async fn fas_service(
    ip: String,
    port: u16,
    db_addr: String,
    fas_key: String,
    auth_dir: String,
) -> Result<()> {
    let addr = SocketAddr::from((
        IpAddr::from_str(&ip).unwrap_or(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        port,
    ));
    let fas_ctx = FasServCtx::new(db_addr, fas_key, auth_dir);

    let app = Router::new()
        .route("/opennds/fas", get(handler))
        .fallback(
            get_service(ServeDir::new("/etc/fika_easy_setup/assets")).handle_error(handle_error),
        )
        .layer(Extension(fas_ctx))
        .layer(TraceLayer::new_for_http())
        .into_make_service_with_connect_info::<SocketAddr>();

    info!("listening on {} for OpenNDS/FAS service", addr);

    axum::Server::bind(&addr)
        .serve(app)
        .await
        .or(Err(anyhow::anyhow!("FAS service start fail")))
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[allow(dead_code)]
struct FasQuery {
    fas: String,
    username: Option<String>,
    emailaddr: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct QueryParams {
    hid: String,
    clientip: String,
    clientmac: String,
    client_type: String,
    gatewayname: String,
    gatewayurl: String,
    version: String,
    gatewayaddress: String,
    gatewaymac: String,
    originurl: String,
    clientif: String,
    themespec: String,
    banner3_message: String,
    banner2_message: String,
    banner1_message: String,
    logo_message: String,
    input: String,
    access_code: String,
    membership_number: String,
    banner3_jpg: String,
    banner2_jpg: String,
    banner1_jpg: String,
    logo_png: String,
    advert1_htm: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
struct PostponeParams {
    posturl: String,
    tok: String,
    redir: Option<String>,
    custom: Option<String>,
}

impl QueryParams {
    fn builder(&self, fas_ctx: &FasServCtx) -> Result<PostponeParams> {
        let mut hasher = Sha256::new();
        hasher.update(&format!("{}{}", &self.hid, fas_ctx.fas_key));
        /* https://users.rust-lang.org/t/sha256-result-to-string/49391/2 */
        let tok = format!("{:x}", hasher.finalize());

        Ok(PostponeParams {
            posturl: format!("{}/{}", &self.gatewayaddress, &fas_ctx.auth_dir),
            tok,
            redir: Some(format!("https://play.google.com/store/apps")),
            custom: Some(format!("koralden+fikapark")),
        })
    }
}

const FAS_TEMP: &str = std::include_str!("../templates/opennds_fas.html");
async fn handler(
    req: Query<FasQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(fas_ctx): Extension<FasServCtx>,
) -> impl IntoResponse {
    dbg!(addr);

    let mut pp_params = PostponeParams::default();
    if let Ok(d64) = base64::decode(&req.fas) {
        debug!("Base64-{:?} Vec try decode as String", &d64);
        if let Ok(query) = String::from_utf8(d64) {
            let qs_non_strict = serde_qs::Config::new(24, false);
            if let Ok(params) = qs_non_strict.deserialize_str::<QueryParams>(&query) {
                debug!("query-string deserialize as {:?}", params);

                if let Ok(pp) = params.builder(&fas_ctx) {
                    info!(
                        "client-{}/{} fas authenticate for {} success",
                        params.clientip, params.clientmac, params.originurl
                    );

                    let _ = tokio::task::spawn_blocking(move || {
                        let _ = fas_ctx.client_track(&params);
                    })
                    .await;

                    debug!("build {:?} success", pp);
                    pp_params = pp;
                }
            } else {
                error!("query-string-{} deserialize fail", query);
            }
        } else {
            error!("Vec<u8> => String fail");
        }
    } else {
        error!("query string-{} base64 decode fail", req.fas);
    }
    return Html(FAS_TEMP.replace("{{ params }}", &serde_json::to_string(&pp_params).unwrap()))
        .into_response();
}

async fn handle_error(_err: io::Error) -> impl IntoResponse {
    (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong...")
}
