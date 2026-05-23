//! Headless REST API for Lancer.
//!
//! Endpoints (token-authenticated via `Authorization: Bearer <token>`):
//!
//!   GET  /v1/status                         — readiness
//!   GET  /v1/history?limit=N                — list captured requests
//!   GET  /v1/history/{id}                   — get one
//!   POST /v1/scan/passive {url}             — run passive checks on URL
//!   POST /v1/scan/active  {request, scheme} — run active checks on a raw request
//!   POST /v1/scan/full    {url}             — passive + active in one call
//!   GET  /v1/issues                         — list stored issues
//!   GET  /v1/report?format=html|json|...    — render report
//!   POST /v1/repeater     {request, scheme} — send + return response
//!   POST /v1/intruder     {…}               — run an intruder attack
//!   GET  /v1/openapi.json                   — machine-readable description

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use lancer_core::HttpRequest;
use lancer_scanner::config::ScanConfig;
use lancer_scanner::ScanEngine;
use lancer_storage::Storage;
use lancer_tools::HttpClient;
use parking_lot::RwLock;
use tokio::net::TcpListener;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "lancer-api", about = "Lancer headless REST API")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9191")]
    listen: SocketAddr,
    #[arg(long, env = "LANCER_API_TOKEN")]
    token: Option<String>,
    #[arg(long)]
    project: Option<std::path::PathBuf>,
}

struct AppState {
    token: Option<String>,
    project: RwLock<Option<Storage>>,
    client: HttpClient,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    let storage = match &args.project {
        Some(p) => Some(Storage::open(p).await?),
        None => None,
    };
    let state = Arc::new(AppState {
        token: args.token,
        project: RwLock::new(storage),
        client: HttpClient::new(),
    });

    let listener = TcpListener::bind(args.listen).await?;
    info!("Lancer API listening on http://{}", args.listen);
    loop {
        let (sock, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(handle(state, req).await) }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(sock), svc)
                .await
            {
                warn!(?peer, "api conn end: {e}");
            }
        });
    }
}

async fn handle(state: Arc<AppState>, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    if let Some(token) = &state.token {
        let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
        if !auth.eq_ignore_ascii_case(&format!("Bearer {token}")) {
            return text(StatusCode::UNAUTHORIZED, "unauthorized");
        }
    }
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes().to_vec(),
        Err(_) => return text(StatusCode::BAD_REQUEST, "bad body"),
    };

    match (method, path.as_str()) {
        (Method::GET, "/v1/status") => json(&serde_json::json!({
            "ok": true,
            "version": env!("CARGO_PKG_VERSION"),
            "project_open": state.project.read().is_some(),
        })),
        (Method::GET, "/v1/openapi.json") => json(&openapi_doc()),
        (Method::GET, "/v1/history") => history_list(&state, parts.uri.query().unwrap_or("")).await,
        (Method::POST, "/v1/scan/passive") => scan_passive(&state, &body_bytes).await,
        (Method::POST, "/v1/scan/active") => scan_active(&state, &body_bytes).await,
        (Method::POST, "/v1/scan/full") => scan_full(&state, &body_bytes).await,
        (Method::GET, "/v1/issues") => issues_list(&state).await,
        (Method::GET, "/v1/report") => report(&state, parts.uri.query().unwrap_or("")).await,
        (Method::POST, "/v1/repeater") => repeater(&state, &body_bytes).await,
        _ => text(StatusCode::NOT_FOUND, "not found"),
    }
}

async fn history_list(state: &AppState, query: &str) -> Response<Full<Bytes>> {
    let storage = state.project.read().clone();
    let Some(storage) = storage else { return text(StatusCode::CONFLICT, "no project open") };
    let limit = parse_query(query, "limit").and_then(|v| v.parse().ok()).unwrap_or(50);
    match storage.history().list(&lancer_storage::HistoryFilter { limit: Some(limit), ..Default::default() }).await {
        Ok(rows) => json(&rows),
        Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn scan_passive(state: &AppState, body: &[u8]) -> Response<Full<Bytes>> {
    #[derive(serde::Deserialize)]
    struct R { url: String }
    let Ok(r) = serde_json::from_slice::<R>(body) else { return text(StatusCode::BAD_REQUEST, "bad json") };
    let engine = ScanEngine::new(ScanConfig::default(), state.client.clone(), state.project.read().as_ref().map(|s| s.issues()));
    let Ok(req) = HttpRequest::builder("GET", &r.url) else { return text(StatusCode::BAD_REQUEST, "bad url") };
    match state.client.send(&req).await {
        Ok(resp) => json(&engine.run_passive(&req, &resp).await),
        Err(e) => text(StatusCode::BAD_GATEWAY, &e.to_string()),
    }
}

async fn scan_active(state: &AppState, body: &[u8]) -> Response<Full<Bytes>> {
    #[derive(serde::Deserialize)]
    struct R { request: String, scheme: Option<String> }
    let Ok(r) = serde_json::from_slice::<R>(body) else { return text(StatusCode::BAD_REQUEST, "bad json") };
    let Ok(mut req) = HttpRequest::parse_wire(r.request.as_bytes()) else { return text(StatusCode::BAD_REQUEST, "bad request") };
    req.meta.scheme = r.scheme.unwrap_or_else(|| "https".into());
    let engine = ScanEngine::new(ScanConfig::default(), state.client.clone(), state.project.read().as_ref().map(|s| s.issues()));
    match engine.run_active(&req).await {
        Ok(issues) => json(&issues),
        Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn scan_full(state: &AppState, body: &[u8]) -> Response<Full<Bytes>> {
    #[derive(serde::Deserialize)]
    struct R { url: String }
    let Ok(r) = serde_json::from_slice::<R>(body) else { return text(StatusCode::BAD_REQUEST, "bad json") };
    let Ok(req) = HttpRequest::builder("GET", &r.url) else { return text(StatusCode::BAD_REQUEST, "bad url") };
    let engine = ScanEngine::new(ScanConfig::default(), state.client.clone(), state.project.read().as_ref().map(|s| s.issues()));
    let resp = match state.client.send(&req).await {
        Ok(r) => r,
        Err(e) => return text(StatusCode::BAD_GATEWAY, &e.to_string()),
    };
    let mut all = engine.run_passive(&req, &resp).await;
    if let Ok(active) = engine.run_active(&req).await {
        all.extend(active);
    }
    json(&all)
}

async fn issues_list(state: &AppState) -> Response<Full<Bytes>> {
    let storage = state.project.read().clone();
    let Some(storage) = storage else { return text(StatusCode::CONFLICT, "no project open") };
    match storage.issues().list().await {
        Ok(rows) => json(&rows),
        Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn report(state: &AppState, query: &str) -> Response<Full<Bytes>> {
    use lancer_report::{render_html, render_json, render_markdown, render_sarif, render_xml, ReportFilter, ReportMeta};
    let storage = state.project.read().clone();
    let Some(storage) = storage else { return text(StatusCode::CONFLICT, "no project open") };
    let Ok(issues) = storage.issues().list().await else { return text(StatusCode::INTERNAL_SERVER_ERROR, "db") };
    let fmt = parse_query(query, "format").unwrap_or_else(|| "json".into());
    let meta = ReportMeta::new("Lancer project");
    let f = ReportFilter::default();
    let (ct, body) = match fmt.as_str() {
        "html" => ("text/html; charset=utf-8", render_html(&meta, &issues, &f)),
        "json" => ("application/json", render_json(&meta, &issues, &f)),
        "markdown" => ("text/markdown", render_markdown(&meta, &issues, &f)),
        "sarif" => ("application/sarif+json", render_sarif(&meta, &issues, &f)),
        "xml" => ("application/xml", render_xml(&meta, &issues, &f)),
        _ => return text(StatusCode::BAD_REQUEST, "unknown format"),
    };
    Response::builder()
        .status(200)
        .header("content-type", ct)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

async fn repeater(state: &AppState, body: &[u8]) -> Response<Full<Bytes>> {
    #[derive(serde::Deserialize)]
    struct R { request: String, scheme: Option<String> }
    let Ok(r) = serde_json::from_slice::<R>(body) else { return text(StatusCode::BAD_REQUEST, "bad json") };
    let Ok(mut req) = HttpRequest::parse_wire(r.request.as_bytes()) else { return text(StatusCode::BAD_REQUEST, "bad request") };
    req.meta.scheme = r.scheme.unwrap_or_else(|| "https".into());
    match state.client.send(&req).await {
        Ok(resp) => json(&serde_json::json!({
            "status": resp.status,
            "headers": resp.headers,
            "body": resp.body_text().unwrap_or(""),
        })),
        Err(e) => text(StatusCode::BAD_GATEWAY, &e.to_string()),
    }
}

fn parse_query(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some(rest) = pair.strip_prefix(&format!("{key}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

fn text(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

fn json<T: serde::Serialize>(v: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(v).unwrap_or_default();
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn openapi_doc() -> serde_json::Value {
    serde_json::json!({
        "openapi": "3.1.0",
        "info": { "title": "Lancer", "version": env!("CARGO_PKG_VERSION") },
        "paths": {
            "/v1/status": { "get": { "summary": "Readiness check" } },
            "/v1/history": { "get": { "summary": "List captured requests" } },
            "/v1/issues": { "get": { "summary": "List stored issues" } },
            "/v1/scan/passive": { "post": { "summary": "Run passive checks on a URL" } },
            "/v1/scan/active": { "post": { "summary": "Run active checks on a raw request" } },
            "/v1/scan/full": { "post": { "summary": "Passive + active on a URL" } },
            "/v1/report": { "get": { "summary": "Render report" } },
            "/v1/repeater": { "post": { "summary": "Send a single request" } },
        }
    })
}
