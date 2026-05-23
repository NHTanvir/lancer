//! Shared GUI state + dev HTTP server.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use lancer_plugin::CommandPalette;
use lancer_script::ScriptEngine;
use lancer_session::SessionEngine;
use lancer_tools::HttpClient;
use parking_lot::RwLock;
use tokio::net::TcpListener;
use tracing::info;

pub struct AppState {
    pub client: HttpClient,
    pub script: ScriptEngine,
    pub palette: CommandPalette,
    pub session: SessionEngine,
    pub project: RwLock<Option<lancer_storage::Storage>>,
}

impl AppState {
    pub async fn new() -> Result<Arc<Self>> {
        let jar = lancer_session::CookieJar::new();
        Ok(Arc::new(Self {
            client: HttpClient::new(),
            script: ScriptEngine::new(),
            palette: CommandPalette::new(),
            session: SessionEngine::new(jar),
            project: RwLock::new(None),
        }))
    }
}

pub async fn run_dev_server(state: Arc<AppState>) -> Result<()> {
    let addr: SocketAddr = std::env::var("LANCER_GUI_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:7878".parse().unwrap());
    let listener = TcpListener::bind(addr).await?;
    info!("Lancer GUI dev server: http://{addr}");
    info!("(Tauri shell not yet enabled — use `--features tauri` once webkit is installed.)");
    loop {
        let (sock, _peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(route(state, req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(sock), svc)
                .await;
        });
    }
}

async fn route(state: Arc<AppState>, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_string();
    match (req.method().as_str(), path.as_str()) {
        ("GET", "/") => html_response(crate::static_assets::INDEX_HTML),
        ("GET", "/api/palette") => {
            let q = req
                .uri()
                .query()
                .and_then(|s| {
                    s.split('&')
                        .find_map(|pair| pair.strip_prefix("q="))
                        .map(|v| v.to_string())
                })
                .unwrap_or_default();
            let cmds = state.palette.search(&q);
            json_response(&cmds)
        }
        ("GET", "/api/status") => {
            json_response(&serde_json::json!({
                "ok": true,
                "version": env!("CARGO_PKG_VERSION"),
            }))
        }
        _ => Response::builder()
            .status(404)
            .body(Full::new(Bytes::from_static(b"not found")))
            .unwrap(),
    }
}

fn html_response(body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(200)
        .header("content-type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

fn json_response<T: serde::Serialize>(v: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec_pretty(v).unwrap_or_default();
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}
