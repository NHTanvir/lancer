//! GUI HTTP server.
//!
//! Hosts the embedded Svelte SPA on `/`, the lightweight palette/status routes
//! on `/api/palette` and `/api/status`, and proxies `/api/v1/*` to the
//! companion `lancer-api` process (spawned by main.rs) at API_BACKEND_ADDR.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use lancer_plugin::CommandPalette;
use lancer_script::ScriptEngine;
use lancer_session::SessionEngine;
use lancer_tools::HttpClient;
use parking_lot::RwLock;
use tokio::net::TcpListener;
use tracing::info;

use crate::static_assets;

pub struct AppState {
    pub client: HttpClient,
    pub script: ScriptEngine,
    pub palette: CommandPalette,
    pub session: SessionEngine,
    pub project: RwLock<Option<lancer_storage::Storage>>,
    /// `host:port` of the spawned lancer-api backend (for /api/v1/* proxy).
    pub api_backend: String,
}

impl AppState {
    pub async fn new(api_backend: String) -> Result<Arc<Self>> {
        let jar = lancer_session::CookieJar::new();
        Ok(Arc::new(Self {
            client: HttpClient::new(),
            script: ScriptEngine::new(),
            palette: CommandPalette::new(),
            session: SessionEngine::new(jar),
            project: RwLock::new(None),
            api_backend,
        }))
    }
}

pub async fn serve(state: Arc<AppState>, addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("Lancer GUI server: http://{addr}");
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

async fn route(
    state: Arc<AppState>,
    req: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|s| s.to_string());

    // --- GUI-local endpoints ---
    if method == Method::GET && path == "/api/palette" {
        let q = query
            .as_deref()
            .and_then(|s| {
                s.split('&')
                    .find_map(|pair| pair.strip_prefix("q="))
                    .map(|v| v.to_string())
            })
            .unwrap_or_default();
        return json(&state.palette.search(&q));
    }
    if method == Method::GET && path == "/api/status" {
        return json(&serde_json::json!({
            "ok": true,
            "version": env!("CARGO_PKG_VERSION"),
        }));
    }

    // --- /api/v1/* proxy to spawned lancer-api ---
    if let Some(suffix) = path.strip_prefix("/api/v1/") {
        return proxy_to_api(&state.api_backend, &method, suffix, query.as_deref(), req).await;
    }
    if path == "/api/v1" {
        return proxy_to_api(&state.api_backend, &method, "", query.as_deref(), req).await;
    }

    // --- embedded SPA ---
    if method == Method::GET {
        if let Some((bytes, ct)) = static_assets::lookup(&path) {
            return Response::builder()
                .status(200)
                .header("content-type", ct)
                .body(Full::new(Bytes::from_static(bytes)))
                .unwrap();
        }
        // SPA fallback for client-side routes ("/repeater", "/history", …)
        if let Some((bytes, ct)) = static_assets::lookup("/index.html") {
            return Response::builder()
                .status(200)
                .header("content-type", ct)
                .body(Full::new(Bytes::from_static(bytes)))
                .unwrap();
        }
        return Response::builder()
            .status(200)
            .header("content-type", "text/html; charset=utf-8")
            .body(Full::new(Bytes::from_static(
                static_assets::FALLBACK_INDEX_HTML.as_bytes(),
            )))
            .unwrap();
    }

    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from_static(b"not found")))
        .unwrap()
}

async fn proxy_to_api(
    backend: &str,
    method: &Method,
    suffix: &str,
    query: Option<&str>,
    req: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    use hyper::client::conn::http1::handshake;
    use tokio::net::TcpStream;

    // Build upstream URI
    let mut upstream_path = format!("/v1/{suffix}");
    if let Some(q) = query {
        upstream_path.push('?');
        upstream_path.push_str(q);
    }

    let stream = match TcpStream::connect(backend).await {
        Ok(s) => s,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!(
                    "API backend unavailable: {e}"
                ))))
                .unwrap();
        }
    };
    let (mut sender, conn) = match handshake::<_, Full<Bytes>>(TokioIo::new(stream)).await {
        Ok(p) => p,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!("handshake: {e}"))))
                .unwrap();
        }
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from(format!("body: {e}"))))
                .unwrap();
        }
    };
    let mut upstream = Request::builder()
        .method(method.clone())
        .uri(upstream_path)
        .header("host", backend);
    for (k, v) in parts.headers.iter() {
        if matches!(
            k.as_str().to_ascii_lowercase().as_str(),
            "host" | "content-length"
        ) {
            continue;
        }
        upstream = upstream.header(k, v);
    }
    let upstream_req = match upstream.body(Full::new(body_bytes)) {
        Ok(r) => r,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from(format!("build req: {e}"))))
                .unwrap();
        }
    };
    let resp = match sender.send_request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!("upstream: {e}"))))
                .unwrap();
        }
    };
    let (resp_parts, resp_body) = resp.into_parts();
    let resp_bytes = resp_body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let mut builder = Response::builder().status(resp_parts.status);
    for (k, v) in resp_parts.headers.iter() {
        if matches!(
            k.as_str().to_ascii_lowercase().as_str(),
            "content-length" | "transfer-encoding"
        ) {
            continue;
        }
        builder = builder.header(k, v);
    }
    builder.body(Full::new(resp_bytes)).unwrap()
}

fn json<T: serde::Serialize>(v: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(v).unwrap_or_default();
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}
