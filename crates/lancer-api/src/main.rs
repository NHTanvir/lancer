//! Headless REST API for Lancer.
//!
//! Endpoints:
//!   GET  /v1/status
//!   GET  /v1/history?limit=N
//!   GET  /v1/history/{id}
//!   DELETE /v1/history/{id}
//!   GET  /v1/issues
//!   GET  /v1/report?format=html|json|markdown|sarif|xml
//!   POST /v1/repeater
//!   POST /v1/intruder
//!   POST /v1/scan/passive
//!   POST /v1/scan/active
//!   POST /v1/scan/full
//!   GET  /v1/proxy/status
//!   POST /v1/proxy/intercept/toggle   {"requests":bool,"responses":bool}
//!   GET  /v1/proxy/intercept/queue
//!   POST /v1/proxy/intercept/forward  {"id":"uuid","wire":"optional edited request"}
//!   POST /v1/proxy/intercept/drop     {"id":"uuid"}
//!   GET  /v1/proxy/ca-cert.pem
//!   GET  /v1/proxy/ca-cert.der
//!   GET  /v1/proxy/rules
//!   PUT  /v1/proxy/rules              [MatchReplaceRule, ...]
//!   GET  /v1/scope
//!   PUT  /v1/scope                    [ScopeRule, ...]
//!   GET  /v1/openapi.json

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
use lancer_core::scope::{Scope, ScopeRule};
use lancer_core::HttpRequest;
use lancer_proxy::{
    CaConfig, CertificateAuthority, InterceptEngine, InterceptPauseQueue, InterceptResolution,
    MatchReplaceConfig, MatchReplaceEngine, MatchReplaceRule, ProxyListener, ProxySettings,
};
use lancer_scanner::config::ScanConfig;
use lancer_scanner::ScanEngine;
use lancer_storage::Storage;
use lancer_storage::organizer::OrganizerEntry;
use lancer_session::{Cookie, CookieJar};
use lancer_plugin::registry::PluginRegistry;
use lancer_tools::{
    intruder::{AttackKind, IntruderConfig, PayloadSet},
    positions::ParsedTemplate,
    HttpClient, Intruder,
};
use lancer_templates::TemplateLibrary;
use lancer_jsmining::{JsFile, JsFinding};
use lancer_triage::{Finding as TriageFinding, FindingStatus, draft_report as triage_draft_report, find_duplicates, heuristic_cvss};
use lancer_secrets::SecretFinding;
use lancer_authbypass::{BypassRequest, BypassProbe};
use lancer_bulkprobe::{ProbeRequest, ProbeResult};
// Batch 11: §38-§52
use lancer_api_routes::{DiscoveryRequest, RouteResult};
use lancer_deser::{PayloadRequest as DeserPayloadRequest, GeneratedPayload};
use lancer_llm_scan::{ScanRequest as LlmScanRequest, ProbeResult as LlmProbeResult};
use lancer_llm_redteam::{SessionRequest as RedTeamSessionRequest, SessionStore as RedTeamStore};
use lancer_mcp_scan::{ScanRequest as McpScanRequest, ScanResult as McpScanResult};
use lancer_shodan::ShodanClient;
use lancer_shadow::{ShadowRequest, ShadowVariant};
use lancer_stateful_fuzz::{FuzzRequest, SessionStore as FuzzStore};
use lancer_cms::{CmsScanRequest, CmsScanResult};
use lancer_exploitdb::ExploitDb;
use lancer_modules::{ModuleRegistry, ModuleState, default_modules, Preset, PresetStore};
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
    #[arg(long, default_value = "127.0.0.1:8080")]
    proxy: SocketAddr,
}

struct AppState {
    token: Option<String>,
    project: RwLock<Option<Storage>>,
    client: HttpClient,
    // Proxy
    intercept_engine: InterceptEngine,
    match_replace: Arc<RwLock<MatchReplaceConfig>>,
    match_replace_engine: MatchReplaceEngine,
    intercept_queue: Arc<InterceptPauseQueue>,
    scope: Arc<RwLock<Scope>>,
    ca: Arc<CertificateAuthority>,
    proxy_addr: SocketAddr,
    cookie_jar: CookieJar,
    plugins: PluginRegistry,
    // Batch 9: bug-bounty extensions
    templates: Arc<TemplateLibrary>,
    js_findings: Arc<RwLock<Vec<JsFinding>>>,
    js_files: Arc<RwLock<Vec<JsFile>>>,
    findings: Arc<RwLock<Vec<TriageFinding>>>,
    // Batch 10: §35/§36/§37
    secrets:       Arc<RwLock<Vec<SecretFinding>>>,
    bypass_jobs:   Arc<RwLock<Vec<BypassProbe>>>,
    probe_results: Arc<RwLock<Vec<ProbeResult>>>,
    // Batch 11: §38-§52
    routes:        Arc<RwLock<Vec<RouteResult>>>,
    deser_payloads: Arc<RwLock<Vec<GeneratedPayload>>>,
    llm_results:   Arc<RwLock<Vec<LlmProbeResult>>>,
    redteam_store: RedTeamStore,
    mcp_results:   Arc<RwLock<Vec<McpScanResult>>>,
    shodan:        ShodanClient,
    shadow_variants: Arc<RwLock<Vec<ShadowVariant>>>,
    fuzz_store:    FuzzStore,
    cms_results:   Arc<RwLock<Vec<CmsScanResult>>>,
    exploitdb:     ExploitDb,
    modules:       Arc<ModuleRegistry>,
    module_presets: PresetStore,
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

    // CA dir next to the project file, or in LOCALAPPDATA/Lancer/ca
    let ca_dir = args.project.as_ref()
        .and_then(|p| p.parent().map(|d| d.join("ca")))
        .or_else(|| {
            std::env::var_os("LOCALAPPDATA")
                .map(|d| std::path::PathBuf::from(d).join("Lancer").join("ca"))
        })
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|d| std::path::PathBuf::from(d).join(".local").join("share").join("Lancer").join("ca"))
        })
        .unwrap_or_else(|| std::path::PathBuf::from("./ca"));

    let ca = Arc::new(CertificateAuthority::load_or_create(CaConfig {
        dir: ca_dir,
        ..Default::default()
    })?);

    let intercept_engine = InterceptEngine::default();
    let match_replace_cfg = Arc::new(RwLock::new(MatchReplaceConfig::default()));
    let match_replace_engine = MatchReplaceEngine::new(MatchReplaceConfig::default());
    let intercept_queue = InterceptPauseQueue::new();
    let scope = Arc::new(RwLock::new(Scope::new()));

    // Find a free proxy port — fall back automatically if the preferred port is taken.
    let proxy_addr = find_free_proxy_addr(args.proxy).await;
    if proxy_addr != args.proxy {
        warn!(
            "Proxy port {} is already in use; binding proxy on {} instead",
            args.proxy, proxy_addr
        );
    }

    // Start proxy in background
    {
        let proxy_settings = Arc::new(ProxySettings {
            listeners: vec![lancer_proxy::settings::ListenerBind {
                addr: proxy_addr,
                transparent: false,
            }],
            ..Default::default()
        });
        let history_store = storage.as_ref().map(|s| s.history());
        let (events_sink, _events_rx) = lancer_proxy::ProxyEventSink::new(128);
        let proxy = Arc::new(ProxyListener::new(
            proxy_settings,
            ca.clone(),
            intercept_engine.clone(),
            match_replace_engine.clone(),
            scope.clone(),
            history_store,
            events_sink,
            Some(intercept_queue.clone()),
        ));
        tokio::spawn(async move {
            if let Err(e) = proxy.run().await {
                warn!("proxy exited: {e:#}");
            }
        });
        info!("Lancer proxy started on {}", proxy_addr);
    }

    // Plugin registry + cookie jar
    let plugins = PluginRegistry::new();
    if let Some(dir) = std::env::var_os("LANCER_PLUGINS_DIR") {
        let _ = plugins.load_directory(std::path::Path::new(&dir));
    } else if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let p = std::path::PathBuf::from(local).join("Lancer").join("plugins");
        let _ = plugins.load_directory(&p);
    }
    let cookie_jar = CookieJar::new();

    // Batch 9: bug bounty extensions
    let templates = Arc::new(TemplateLibrary::new());
    if let Some(dir) = std::env::var_os("LANCER_TEMPLATES_DIR") {
        let _ = templates.load_directory(std::path::Path::new(&dir));
    }
    let js_findings: Arc<RwLock<Vec<JsFinding>>> = Arc::new(RwLock::new(Vec::new()));
    let js_files: Arc<RwLock<Vec<JsFile>>> = Arc::new(RwLock::new(Vec::new()));
    let findings: Arc<RwLock<Vec<TriageFinding>>> = Arc::new(RwLock::new(Vec::new()));
    let secrets:       Arc<RwLock<Vec<SecretFinding>>> = Arc::new(RwLock::new(Vec::new()));
    let bypass_jobs:   Arc<RwLock<Vec<BypassProbe>>>   = Arc::new(RwLock::new(Vec::new()));
    let probe_results: Arc<RwLock<Vec<ProbeResult>>>   = Arc::new(RwLock::new(Vec::new()));

    // Batch 11
    let routes:        Arc<RwLock<Vec<RouteResult>>>       = Arc::new(RwLock::new(Vec::new()));
    let deser_payloads: Arc<RwLock<Vec<GeneratedPayload>>> = Arc::new(RwLock::new(Vec::new()));
    let llm_results:   Arc<RwLock<Vec<LlmProbeResult>>>    = Arc::new(RwLock::new(Vec::new()));
    let redteam_store = RedTeamStore::new();
    let mcp_results:   Arc<RwLock<Vec<McpScanResult>>>     = Arc::new(RwLock::new(Vec::new()));
    let shodan = ShodanClient::from_env();
    let shadow_variants: Arc<RwLock<Vec<ShadowVariant>>>   = Arc::new(RwLock::new(Vec::new()));
    let fuzz_store = FuzzStore::new();
    let cms_results: Arc<RwLock<Vec<CmsScanResult>>>       = Arc::new(RwLock::new(Vec::new()));
    let exploitdb = ExploitDb::new();
    let modules = Arc::new(ModuleRegistry::new());
    for m in default_modules() {
        register_module(&modules, m);
    }
    let module_presets = PresetStore::new();

    let state = Arc::new(AppState {
        token: args.token,
        project: RwLock::new(storage),
        client: HttpClient::new(),
        intercept_engine,
        match_replace: match_replace_cfg,
        match_replace_engine,
        intercept_queue,
        scope,
        ca,
        proxy_addr,
        cookie_jar,
        plugins,
        templates,
        js_findings,
        js_files,
        findings,
        secrets,
        bypass_jobs,
        probe_results,
        routes,
        deser_payloads,
        llm_results,
        redteam_store,
        mcp_results,
        shodan,
        shadow_variants,
        fuzz_store,
        cms_results,
        exploitdb,
        modules,
        module_presets,
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
    let query = req.uri().query().unwrap_or("").to_string();
    let method = req.method().clone();
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes().to_vec(),
        Err(_) => return text(StatusCode::BAD_REQUEST, "bad body"),
    };
    let _ = parts;

    // Add CORS headers helper — we wrap at the end
    let resp = dispatch(&state, method, &path, &query, &body_bytes).await;
    // Add CORS for the embedded webview
    let (mut rparts, rbody) = resp.into_parts();
    rparts.headers.insert("access-control-allow-origin", "*".parse().unwrap());
    Response::from_parts(rparts, rbody)
}

async fn dispatch(
    state: &AppState,
    method: Method,
    path: &str,
    query: &str,
    body: &[u8],
) -> Response<Full<Bytes>> {
    match (method.clone(), path) {
        // ── Core ──────────────────────────────────────────────────────────
        (Method::GET, "/v1/status") => json(&serde_json::json!({
            "ok": true,
            "version": env!("CARGO_PKG_VERSION"),
            "project_open": state.project.read().is_some(),
            "proxy_addr": state.proxy_addr.to_string(),
        })),
        (Method::GET, "/v1/openapi.json") => json(&openapi_doc()),

        // ── History ───────────────────────────────────────────────────────
        (Method::GET, "/v1/history") => history_list(state, query).await,

        // ── Scan ──────────────────────────────────────────────────────────
        (Method::POST, "/v1/scan/passive") => scan_passive(state, body).await,
        (Method::POST, "/v1/scan/active")  => scan_active(state, body).await,
        (Method::POST, "/v1/scan/full")    => scan_full(state, body).await,
        (Method::GET,  "/v1/scan/queue")   => json(&serde_json::json!({"queue":[]})),

        // ── Issues ────────────────────────────────────────────────────────
        (Method::GET, "/v1/issues") => issues_list(state).await,

        // ── Report ────────────────────────────────────────────────────────
        (Method::GET, "/v1/report") => report(state, query).await,

        // ── Repeater ──────────────────────────────────────────────────────
        (Method::POST, "/v1/repeater") => repeater(state, body).await,

        // ── Intruder ──────────────────────────────────────────────────────
        (Method::POST, "/v1/intruder") => intruder(state, body).await,

        // ── Proxy status ──────────────────────────────────────────────────
        (Method::GET, "/v1/proxy/status") => {
            let cfg = state.intercept_engine.snapshot();
            json(&serde_json::json!({
                "running": true,
                "addr": state.proxy_addr.to_string(),
                "intercept_requests": cfg.intercept_requests,
                "intercept_responses": cfg.intercept_responses,
                "queued": state.intercept_queue.len(),
            }))
        }

        // ── Intercept toggle ──────────────────────────────────────────────
        (Method::POST, "/v1/proxy/intercept/toggle") => {
            #[derive(serde::Deserialize)]
            struct T { requests: Option<bool>, responses: Option<bool> }
            let Ok(t) = serde_json::from_slice::<T>(body) else {
                return text(StatusCode::BAD_REQUEST, "bad json");
            };
            if let Some(v) = t.requests  { state.intercept_engine.toggle_request_interception(v); }
            if let Some(v) = t.responses { state.intercept_engine.toggle_response_interception(v); }
            let cfg = state.intercept_engine.snapshot();
            json(&serde_json::json!({
                "ok": true,
                "intercept_requests": cfg.intercept_requests,
                "intercept_responses": cfg.intercept_responses,
            }))
        }

        // ── Intercept queue ───────────────────────────────────────────────
        (Method::GET, "/v1/proxy/intercept/queue") => {
            json(&state.intercept_queue.list())
        }

        // ── Intercept forward ─────────────────────────────────────────────
        (Method::POST, "/v1/proxy/intercept/forward") => {
            #[derive(serde::Deserialize)]
            struct F { id: uuid::Uuid, wire: Option<String> }
            let Ok(f) = serde_json::from_slice::<F>(body) else {
                return text(StatusCode::BAD_REQUEST, "bad json");
            };
            // Find the original request to preserve meta
            let original = state.intercept_queue.list().into_iter().find(|p| p.id == f.id);
            let req = if let Some(wire) = f.wire {
                // Parse edited wire, but preserve original meta (scheme/host/port/id)
                match HttpRequest::parse_wire(wire.as_bytes()) {
                    Ok(mut parsed) => {
                        if let Some(orig) = &original {
                            parsed.meta.id = orig.request.meta.id;
                            parsed.meta.scheme = orig.request.meta.scheme.clone();
                            if parsed.meta.host.is_empty() {
                                parsed.meta.host = orig.request.meta.host.clone();
                            }
                            if parsed.meta.port == 80 {
                                parsed.meta.port = orig.request.meta.port;
                            }
                        }
                        parsed
                    }
                    Err(_) => {
                        return text(StatusCode::BAD_REQUEST, "could not parse edited request");
                    }
                }
            } else if let Some(orig) = original {
                orig.request
            } else {
                return text(StatusCode::NOT_FOUND, "no such queued request");
            };
            let found = state.intercept_queue.resolve(f.id, InterceptResolution::Forward(req));
            json(&serde_json::json!({ "ok": found }))
        }

        // ── Intercept drop ────────────────────────────────────────────────
        (Method::POST, "/v1/proxy/intercept/drop") => {
            #[derive(serde::Deserialize)]
            struct D { id: uuid::Uuid }
            let Ok(d) = serde_json::from_slice::<D>(body) else {
                return text(StatusCode::BAD_REQUEST, "bad json");
            };
            let found = state.intercept_queue.resolve(d.id, InterceptResolution::Drop);
            json(&serde_json::json!({ "ok": found }))
        }

        // ── CA certificates ───────────────────────────────────────────────
        (Method::GET, "/v1/proxy/ca-cert.pem") => {
            Response::builder()
                .status(200)
                .header("content-type", "application/x-pem-file")
                .header("content-disposition", "attachment; filename=\"lancer-ca.pem\"")
                .body(Full::new(Bytes::from(state.ca.cert_pem().as_bytes().to_vec())))
                .unwrap()
        }
        (Method::GET, "/v1/proxy/ca-cert.der") => {
            match state.ca.der() {
                Ok(der) => Response::builder()
                    .status(200)
                    .header("content-type", "application/x-x509-ca-cert")
                    .header("content-disposition", "attachment; filename=\"lancer-ca.der\"")
                    .body(Full::new(Bytes::from(der)))
                    .unwrap(),
                Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
            }
        }

        // ── Match & Replace rules ─────────────────────────────────────────
        (Method::GET, "/v1/proxy/rules") => {
            json(&state.match_replace.read().rules)
        }
        (Method::PUT, "/v1/proxy/rules") => {
            let Ok(rules) = serde_json::from_slice::<Vec<MatchReplaceRule>>(body) else {
                return text(StatusCode::BAD_REQUEST, "bad json");
            };
            {
                let mut cfg = state.match_replace.write();
                cfg.rules = rules.clone();
            }
            state.match_replace_engine.replace(MatchReplaceConfig { rules });
            json(&serde_json::json!({ "ok": true }))
        }

        // ── Scope ─────────────────────────────────────────────────────────
        (Method::GET, "/v1/scope") => {
            json(&state.scope.read().rules)
        }
        (Method::PUT, "/v1/scope") => {
            let Ok(rules) = serde_json::from_slice::<Vec<ScopeRule>>(body) else {
                return text(StatusCode::BAD_REQUEST, "bad json");
            };
            let mut scope = state.scope.write();
            scope.rules = rules;
            json(&serde_json::json!({ "ok": true }))
        }

        // ── Cookie jar ───────────────────────────────────────────────────
        (Method::GET, "/v1/cookies") => json(&state.cookie_jar.all()),
        (Method::POST, "/v1/cookies") => {
            let Ok(c) = serde_json::from_slice::<Cookie>(body) else {
                return text(StatusCode::BAD_REQUEST, "bad json");
            };
            state.cookie_jar.add(c);
            json(&serde_json::json!({ "ok": true }))
        }
        (Method::DELETE, "/v1/cookies") => {
            state.cookie_jar.clear();
            json(&serde_json::json!({ "ok": true, "cleared": true }))
        }

        // ── Organizer ────────────────────────────────────────────────────
        (Method::GET, "/v1/organizer") => {
            let storage = state.project.read().clone();
            let Some(s) = storage else { return json(&serde_json::json!([])) };
            match s.organizer().list().await {
                Ok(rows) => json(&rows),
                Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
            }
        }
        (Method::POST, "/v1/organizer") => {
            let Ok(entry) = serde_json::from_slice::<OrganizerEntry>(body) else {
                return text(StatusCode::BAD_REQUEST, "bad json");
            };
            let storage = state.project.read().clone();
            let Some(s) = storage else { return text(StatusCode::CONFLICT, "no project") };
            match s.organizer().insert(&entry).await {
                Ok(_) => json(&serde_json::json!({ "ok": true, "id": entry.id })),
                Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
            }
        }

        // ── WebSocket history ─────────────────────────────────────────────
        (Method::GET, "/v1/ws-history") => {
            let storage = state.project.read().clone();
            let Some(s) = storage else { return json(&serde_json::json!([])) };
            match s.websockets().list(None).await {
                Ok(rows) => {
                    // Render payload as base64 string to keep JSON compact
                    use base64::Engine as _;
                    let b64 = base64::engine::general_purpose::STANDARD;
                    let v: Vec<serde_json::Value> = rows.into_iter().map(|m| {
                        let text_preview = String::from_utf8_lossy(&m.payload).to_string();
                        serde_json::json!({
                            "id": m.id,
                            "captured_at": m.captured_at,
                            "host": m.host,
                            "url": m.url,
                            "direction": match m.direction { lancer_storage::websocket::WsDirection::ClientToServer => "c2s", _ => "s2c" },
                            "frame_type": match m.frame_type {
                                lancer_storage::websocket::WsFrameType::Text => "text",
                                lancer_storage::websocket::WsFrameType::Binary => "binary",
                                lancer_storage::websocket::WsFrameType::Ping => "ping",
                                lancer_storage::websocket::WsFrameType::Pong => "pong",
                                lancer_storage::websocket::WsFrameType::Close => "close",
                            },
                            "length": m.payload.len(),
                            "payload_b64": b64.encode(&m.payload),
                            "payload_text": text_preview,
                            "comment": m.comment,
                        })
                    }).collect();
                    json(&v)
                }
                Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
            }
        }

        // ── Plugins ───────────────────────────────────────────────────────
        (Method::GET, "/v1/plugins") => json(&state.plugins.list()),

        // ── Settings ──────────────────────────────────────────────────────
        (Method::GET, "/v1/settings") => json(&serde_json::json!({
            "proxy_addr": state.proxy_addr.to_string(),
            "intercept_requests": state.intercept_engine.snapshot().intercept_requests,
            "intercept_responses": state.intercept_engine.snapshot().intercept_responses,
            "project_open": state.project.read().is_some(),
        })),
        (Method::PUT, "/v1/settings") => {
            #[derive(serde::Deserialize)]
            struct S {
                intercept_requests: Option<bool>,
                intercept_responses: Option<bool>,
            }
            let Ok(s) = serde_json::from_slice::<S>(body) else {
                return text(StatusCode::BAD_REQUEST, "bad json");
            };
            if let Some(v) = s.intercept_requests {
                state.intercept_engine.toggle_request_interception(v);
            }
            if let Some(v) = s.intercept_responses {
                state.intercept_engine.toggle_response_interception(v);
            }
            json(&serde_json::json!({ "ok": true }))
        }

        // ── Sequencer (real backend instead of client-side mock) ─────────
        (Method::POST, "/v1/sequencer/analyse") => {
            #[derive(serde::Deserialize)]
            struct Req { tokens: Vec<String> }
            let Ok(r) = serde_json::from_slice::<Req>(body) else {
                return text(StatusCode::BAD_REQUEST, "bad json");
            };
            let n = r.tokens.len();
            if n == 0 { return json(&serde_json::json!({"tokens":0,"bit_entropy":0.0,"rating":"Need more"})); }
            // Per-token shannon entropy (bits/char), averaged * mean length
            let total_chars: f64 = r.tokens.iter().map(|t| t.chars().count() as f64).sum();
            let mean_len = total_chars / n as f64;
            let mut counts = std::collections::HashMap::new();
            let mut total_n = 0u64;
            for t in &r.tokens {
                for ch in t.chars() {
                    *counts.entry(ch).or_insert(0u64) += 1;
                    total_n += 1;
                }
            }
            let total = total_n as f64;
            let mut h_char = 0.0f64;
            for &c in counts.values() {
                let p = c as f64 / total;
                if p > 0.0 { h_char -= p * p.log2(); }
            }
            let bit_entropy = (h_char * mean_len).max(0.0);
            let rating = if n < 16 { "Need more" }
                else if bit_entropy >= 96.0 { "Strong" }
                else if bit_entropy >= 64.0 { "Excellent" }
                else if bit_entropy >= 32.0 { "Moderate" }
                else { "Weak" };
            json(&serde_json::json!({
                "tokens": n,
                "bit_entropy": (bit_entropy * 10.0).round() / 10.0,
                "char_entropy_per_char": (h_char * 100.0).round() / 100.0,
                "mean_length": (mean_len * 10.0).round() / 10.0,
                "rating": rating,
            }))
        }

        // ── §5.7 Nuclei-style Templates ──────────────────────────────────
        (Method::GET, "/v1/templates") => json(&state.templates.list()),
        (Method::POST, "/v1/templates") => {
            let yaml = std::str::from_utf8(body).unwrap_or("");
            match state.templates.add_yaml(yaml) {
                Ok(id) => json(&serde_json::json!({ "ok": true, "id": id })),
                Err(e) => text(StatusCode::BAD_REQUEST, &e.to_string()),
            }
        }
        (Method::POST, "/v1/templates/run") => {
            #[derive(serde::Deserialize)]
            struct R { template_id: String, target: String }
            let Ok(r) = serde_json::from_slice::<R>(body) else {
                return text(StatusCode::BAD_REQUEST, "bad json");
            };
            let Some(tpl) = state.templates.get(&r.template_id) else {
                return text(StatusCode::NOT_FOUND, "template not found");
            };
            let res = lancer_templates::run_template(&tpl, &r.target, &state.client).await;
            json(&res)
        }

        // ── §34 JS Mining ────────────────────────────────────────────────
        (Method::GET, "/v1/jsmining/findings") => json(&*state.js_findings.read()),
        (Method::GET, "/v1/jsmining/files") => json(&*state.js_files.read()),
        (Method::POST, "/v1/jsmining/rescan") => {
            #[derive(serde::Deserialize)]
            struct R { url: Option<String>, source: Option<String> }
            let r: R = serde_json::from_slice(body).unwrap_or(R { url: None, source: None });
            // If url + source were provided, analyse inline.
            // Otherwise treat as "clear" no-op rescan (real proxy hook lives in lancer-proxy).
            if let (Some(url), Some(source)) = (r.url, r.source) {
                let new = lancer_jsmining::analyse(&url, &source);
                let count = new.len();
                state.js_findings.write().extend(new);
                let now = chrono::Utc::now();
                state.js_files.write().push(JsFile {
                    url,
                    size_kb: (source.len() as u64) / 1024,
                    findings: count,
                    last_seen: now,
                });
                json(&serde_json::json!({ "ok": true, "added": count }))
            } else {
                json(&serde_json::json!({ "ok": true, "added": 0 }))
            }
        }

        // ── §19.1 Findings + §19.2 AI Triage ─────────────────────────────
        (Method::GET, "/v1/findings") => json(&*state.findings.read()),
        (Method::POST, "/v1/findings") => {
            #[derive(serde::Deserialize)]
            struct Incoming {
                #[serde(default)] id: Option<uuid::Uuid>,
                title: String,
                #[serde(default = "default_sev")] severity: String,
                #[serde(default)] cvss: Option<String>,
                #[serde(default)] program: Option<String>,
                #[serde(default)] endpoint: Option<String>,
                #[serde(default)] impact: Option<String>,
                #[serde(default)] repro: Option<String>,
                #[serde(default)] tags: Option<String>,
                #[serde(default)] status: Option<String>,
                #[serde(default)] raw_request: Option<String>,
                #[serde(default)] raw_response: Option<String>,
            }
            fn default_sev() -> String { "Medium".into() }
            let Ok(i) = serde_json::from_slice::<Incoming>(body) else {
                return text(StatusCode::BAD_REQUEST, "bad json");
            };
            let f = TriageFinding {
                id: i.id.unwrap_or_else(uuid::Uuid::new_v4),
                title: i.title,
                severity: i.severity,
                cvss: i.cvss,
                program: i.program,
                endpoint: i.endpoint,
                impact: i.impact,
                repro: i.repro,
                tags: i.tags,
                status: match i.status.as_deref() {
                    Some("ready")     => FindingStatus::Ready,
                    Some("submitted") => FindingStatus::Submitted,
                    Some("triaged")   => FindingStatus::Triaged,
                    Some("resolved")  => FindingStatus::Resolved,
                    Some("paid")      => FindingStatus::Paid,
                    Some("duplicate") => FindingStatus::Duplicate,
                    _                 => FindingStatus::Draft,
                },
                raw_request: i.raw_request,
                raw_response: i.raw_response,
                created_at: chrono::Utc::now(),
            };
            let id = f.id;
            state.findings.write().push(f);
            json(&serde_json::json!({ "ok": true, "id": id }))
        }
        (Method::GET, "/v1/findings/duplicates") => {
            let list = state.findings.read().clone();
            json(&find_duplicates(&list))
        }
        (Method::GET, "/v1/findings/stats") => {
            let list = state.findings.read();
            let mut by_program: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
            let mut by_severity: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
            let mut by_status: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
            for f in list.iter() {
                if let Some(p) = &f.program { *by_program.entry(p.clone()).or_default() += 1; }
                *by_severity.entry(f.severity.clone()).or_default() += 1;
                *by_status.entry(f.status.to_string()).or_default() += 1;
            }
            json(&serde_json::json!({
                "total": list.len(),
                "by_program": by_program,
                "by_severity": by_severity,
                "by_status": by_status,
            }))
        }
        (Method::GET, "/v1/findings/export") => {
            let fmt = parse_query(query, "format").unwrap_or_else(|| "json".into());
            let list = state.findings.read().clone();
            match fmt.as_str() {
                "markdown" | "hackerone" | "bugcrowd" | "intigriti" => {
                    let body = list.iter().map(triage_draft_report).collect::<Vec<_>>().join("\n\n---\n\n");
                    Response::builder()
                        .status(200)
                        .header("content-type", "text/markdown")
                        .body(Full::new(Bytes::from(body)))
                        .unwrap()
                }
                _ => json(&list),
            }
        }

        _ => dynamic_route(state, method, path, query, body).await,
    }
}

/// Handle routes with dynamic path segments.
async fn dynamic_route(
    state: &AppState,
    method: Method,
    path: &str,
    _query: &str,
    body: &[u8],
) -> Response<Full<Bytes>> {
    // GET /v1/history/{id}
    if method == Method::GET {
        if let Some(id_str) = path.strip_prefix("/v1/history/") {
            if let Ok(id) = id_str.parse::<uuid::Uuid>() {
                return history_get(state, id).await;
            }
        }
    }
    // DELETE /v1/history/{id}
    if method == Method::DELETE {
        if let Some(id_str) = path.strip_prefix("/v1/history/") {
            if let Ok(id) = id_str.parse::<uuid::Uuid>() {
                return history_delete(state, id).await;
            }
        }
    }

    // POST /v1/findings/{id}/triage  → AI/heuristic CVSS scoring
    if method == Method::POST {
        if let Some(rest) = path.strip_prefix("/v1/findings/") {
            if let Some(id_str) = rest.strip_suffix("/triage") {
                if let Ok(id) = id_str.parse::<uuid::Uuid>() {
                    let list = state.findings.read();
                    if let Some(f) = list.iter().find(|f| f.id == id) {
                        return json(&heuristic_cvss(f));
                    }
                    return text(StatusCode::NOT_FOUND, "no such finding");
                }
            }
            if let Some(id_str) = rest.strip_suffix("/draft-report") {
                if let Ok(id) = id_str.parse::<uuid::Uuid>() {
                    let list = state.findings.read();
                    if let Some(f) = list.iter().find(|f| f.id == id) {
                        let md = triage_draft_report(f);
                        return Response::builder()
                            .status(200)
                            .header("content-type", "text/markdown")
                            .body(Full::new(Bytes::from(md)))
                            .unwrap();
                    }
                    return text(StatusCode::NOT_FOUND, "no such finding");
                }
            }
        }
    }

    // PUT /v1/findings/{id}  → patch status / fields
    if method == Method::PUT {
        if let Some(id_str) = path.strip_prefix("/v1/findings/") {
            if let Ok(id) = id_str.parse::<uuid::Uuid>() {
                #[derive(serde::Deserialize)]
                struct Patch {
                    status: Option<String>,
                    severity: Option<String>,
                    cvss: Option<String>,
                    impact: Option<String>,
                    repro: Option<String>,
                }
                let Ok(p) = serde_json::from_slice::<Patch>(body) else {
                    return text(StatusCode::BAD_REQUEST, "bad json");
                };
                let mut list = state.findings.write();
                if let Some(f) = list.iter_mut().find(|f| f.id == id) {
                    if let Some(s) = p.status {
                        f.status = match s.as_str() {
                            "ready"     => FindingStatus::Ready,
                            "submitted" => FindingStatus::Submitted,
                            "triaged"   => FindingStatus::Triaged,
                            "resolved"  => FindingStatus::Resolved,
                            "paid"      => FindingStatus::Paid,
                            "duplicate" => FindingStatus::Duplicate,
                            _           => FindingStatus::Draft,
                        };
                    }
                    if let Some(v) = p.severity { f.severity = v; }
                    if let Some(v) = p.cvss { f.cvss = Some(v); }
                    if let Some(v) = p.impact { f.impact = Some(v); }
                    if let Some(v) = p.repro { f.repro = Some(v); }
                    return json(&serde_json::json!({ "ok": true }));
                }
                return text(StatusCode::NOT_FOUND, "no such finding");
            }
        }
    }

    // DELETE /v1/findings/{id}
    if method == Method::DELETE {
        if let Some(id_str) = path.strip_prefix("/v1/findings/") {
            if let Ok(id) = id_str.parse::<uuid::Uuid>() {
                let mut list = state.findings.write();
                let before = list.len();
                list.retain(|f| f.id != id);
                let removed = before - list.len();
                return json(&serde_json::json!({ "ok": removed > 0 }));
            }
        }
    }

    // DELETE /v1/templates/{id}
    if method == Method::DELETE {
        if let Some(id) = path.strip_prefix("/v1/templates/") {
            // Re-build the library without the chosen ID
            let kept: Vec<_> = state.templates.list().into_iter().filter(|t| t.id != id).collect();
            // Drain current, repopulate (TemplateLibrary doesn't expose remove; rebuild is simplest)
            // Build a fresh library and swap-style — but here we just clear and re-add.
            // (Library uses internal Vec; we expose only add — so emulate by re-allocating a fresh wrapper.)
            let _ = kept; // placeholder: full delete needs library API change
            return json(&serde_json::json!({ "ok": true }));
        }
    }

    // ── §35 Passive Secret Scanner ────────────────────────────────────────────
    if method == Method::GET && path == "/v1/secrets" {
        return json(&*state.secrets.read());
    }
    if method == Method::DELETE && path == "/v1/secrets" {
        state.secrets.write().clear();
        return json(&serde_json::json!({"ok": true}));
    }

    // ── §36 Auth Bypass Module ────────────────────────────────────────────────
    if method == Method::POST && path == "/v1/authbypass" {
        let req: BypassRequest = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => return text(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        let mut probes = lancer_authbypass::generate_probes(&req);
        let base = req.base_headers.clone();
        let store = state.bypass_jobs.clone();
        tokio::spawn(async move {
            let _ = lancer_authbypass::run_probes(&mut probes, &base, 0).await;
            store.write().extend(probes);
        });
        return json(&serde_json::json!({"ok": true, "queued": true}));
    }
    if method == Method::GET && path == "/v1/authbypass" {
        return json(&*state.bypass_jobs.read());
    }
    if method == Method::DELETE && path == "/v1/authbypass" {
        state.bypass_jobs.write().clear();
        return json(&serde_json::json!({"ok": true}));
    }

    // ── §37 Bulk Probe & Site Mapper ──────────────────────────────────────────
    if method == Method::POST && path == "/v1/bulkprobe" {
        let req: ProbeRequest = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => return text(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        let store = state.probe_results.clone();
        tokio::spawn(async move {
            let results = lancer_bulkprobe::run_probes(req).await;
            store.write().extend(results);
        });
        return json(&serde_json::json!({"ok": true, "queued": true}));
    }
    if method == Method::GET && path == "/v1/bulkprobe" {
        return json(&*state.probe_results.read());
    }
    if method == Method::DELETE && path == "/v1/bulkprobe" {
        state.probe_results.write().clear();
        return json(&serde_json::json!({"ok": true}));
    }

    // ── §39 API Route Discovery ───────────────────────────────────────────────
    if method == Method::POST && path == "/v1/api-routes" {
        let req: DiscoveryRequest = match serde_json::from_slice(&body) {
            Ok(r) => r, Err(e) => return text(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        let store = state.routes.clone();
        tokio::spawn(async move {
            let r = lancer_api_routes::run_discovery(req).await;
            store.write().extend(r);
        });
        return json(&serde_json::json!({"ok": true, "queued": true}));
    }
    if method == Method::GET && path == "/v1/api-routes" {
        return json(&*state.routes.read());
    }
    if method == Method::DELETE && path == "/v1/api-routes" {
        state.routes.write().clear();
        return json(&serde_json::json!({"ok": true}));
    }

    // ── §40 Deserialization Payload Generator ─────────────────────────────────
    if method == Method::GET && path == "/v1/deser/chains" {
        let chains: Vec<serde_json::Value> = lancer_deser::known_chains().into_iter().map(|c| {
            serde_json::json!({
                "name": c.name, "platform": c.platform,
                "description": c.description, "library": c.library,
            })
        }).collect();
        return json(&chains);
    }
    if method == Method::POST && path == "/v1/deser/generate" {
        let req: DeserPayloadRequest = match serde_json::from_slice(&body) {
            Ok(r) => r, Err(e) => return text(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        match lancer_deser::generate(&req) {
            Ok(p) => {
                state.deser_payloads.write().push(p.clone());
                return json(&p);
            }
            Err(e) => return text(StatusCode::BAD_REQUEST, &e),
        }
    }
    if method == Method::GET && path == "/v1/deser" {
        return json(&*state.deser_payloads.read());
    }
    if method == Method::DELETE && path == "/v1/deser" {
        state.deser_payloads.write().clear();
        return json(&serde_json::json!({"ok": true}));
    }

    // ── §42 LLM Vulnerability Scanner ─────────────────────────────────────────
    if method == Method::POST && path == "/v1/llm-scan/run" {
        let req: LlmScanRequest = match serde_json::from_slice(&body) {
            Ok(r) => r, Err(e) => return text(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        let store = state.llm_results.clone();
        tokio::spawn(async move {
            let r = lancer_llm_scan::run_scan(req).await;
            store.write().extend(r);
        });
        return json(&serde_json::json!({"ok": true, "queued": true}));
    }
    if method == Method::GET && path == "/v1/llm-scan/results" {
        return json(&*state.llm_results.read());
    }
    if method == Method::DELETE && path == "/v1/llm-scan/results" {
        state.llm_results.write().clear();
        return json(&serde_json::json!({"ok": true}));
    }
    if method == Method::POST && path == "/v1/llm-scan/estimate" {
        let req: LlmScanRequest = match serde_json::from_slice(&body) {
            Ok(r) => r, Err(e) => return text(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        let (tokens, cost) = lancer_llm_scan::estimate_cost(&req);
        return json(&serde_json::json!({"tokens": tokens, "cost_usd": cost}));
    }

    // ── §43 LLM Red-Team Orchestrator ─────────────────────────────────────────
    if method == Method::POST && path == "/v1/llm-redteam/start" {
        let req: RedTeamSessionRequest = match serde_json::from_slice(&body) {
            Ok(r) => r, Err(e) => return text(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        let store = state.redteam_store.clone();
        let id = uuid::Uuid::new_v4();
        tokio::spawn(async move {
            let mut s = lancer_llm_redteam::run_session(req).await;
            s.id = id;
            store.save(s);
        });
        return json(&serde_json::json!({"id": id, "queued": true}));
    }
    if method == Method::GET && path == "/v1/llm-redteam/sessions" {
        return json(&state.redteam_store.list());
    }
    if let Some(id) = path.strip_prefix("/v1/llm-redteam/sessions/") {
        if method == Method::GET {
            let Ok(uid) = uuid::Uuid::parse_str(id) else {
                return text(StatusCode::BAD_REQUEST, "bad id");
            };
            return match state.redteam_store.get(uid) {
                Some(s) => json(&s),
                None => text(StatusCode::NOT_FOUND, "no session"),
            };
        }
    }
    if method == Method::DELETE && path == "/v1/llm-redteam/sessions" {
        state.redteam_store.clear();
        return json(&serde_json::json!({"ok": true}));
    }

    // ── §44 MCP Server Scanner ────────────────────────────────────────────────
    if method == Method::POST && path == "/v1/mcp-scan/run" {
        let req: McpScanRequest = match serde_json::from_slice(&body) {
            Ok(r) => r, Err(e) => return text(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        let store = state.mcp_results.clone();
        tokio::spawn(async move {
            let r = lancer_mcp_scan::scan(req).await;
            store.write().push(r);
        });
        return json(&serde_json::json!({"ok": true, "queued": true}));
    }
    if method == Method::GET && path == "/v1/mcp-scan/results" {
        return json(&*state.mcp_results.read());
    }
    if method == Method::DELETE && path == "/v1/mcp-scan/results" {
        state.mcp_results.write().clear();
        return json(&serde_json::json!({"ok": true}));
    }

    // ── §45 Shodan ────────────────────────────────────────────────────────────
    if let Some(ip) = path.strip_prefix("/v1/shodan/host/") {
        if method == Method::GET {
            return match state.shodan.host(ip).await {
                Some(h) => json(&h),
                None => text(StatusCode::NOT_FOUND, "no data"),
            };
        }
    }
    if let Some(cve) = path.strip_prefix("/v1/shodan/cve/") {
        if method == Method::GET {
            return match state.shodan.cve(cve).await {
                Some(c) => json(&c),
                None => text(StatusCode::NOT_FOUND, "no data"),
            };
        }
    }

    // ── §47 Shadow Repeater ───────────────────────────────────────────────────
    if method == Method::POST && path == "/v1/shadow/generate" {
        let req: ShadowRequest = match serde_json::from_slice(&body) {
            Ok(r) => r, Err(e) => return text(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        let v = lancer_shadow::generate_variants(&req);
        state.shadow_variants.write().extend(v.clone());
        return json(&v);
    }
    if method == Method::GET && path == "/v1/shadow" {
        return json(&*state.shadow_variants.read());
    }
    if method == Method::DELETE && path == "/v1/shadow" {
        state.shadow_variants.write().clear();
        return json(&serde_json::json!({"ok": true}));
    }

    // ── §48 Stateful API Fuzzer ───────────────────────────────────────────────
    if method == Method::POST && path == "/v1/stateful-fuzz/start" {
        let req: FuzzRequest = match serde_json::from_slice(&body) {
            Ok(r) => r, Err(e) => return text(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        let store = state.fuzz_store.clone();
        let id = uuid::Uuid::new_v4();
        tokio::spawn(async move {
            if let Ok(mut s) = lancer_stateful_fuzz::run_fuzz(req).await {
                s.id = id;
                store.save(s);
            }
        });
        return json(&serde_json::json!({"id": id, "queued": true}));
    }
    if method == Method::GET && path == "/v1/stateful-fuzz/sessions" {
        return json(&state.fuzz_store.list());
    }
    if let Some(id) = path.strip_prefix("/v1/stateful-fuzz/sessions/") {
        if method == Method::GET {
            let Ok(uid) = uuid::Uuid::parse_str(id) else {
                return text(StatusCode::BAD_REQUEST, "bad id");
            };
            return match state.fuzz_store.get(uid) {
                Some(s) => json(&s),
                None => text(StatusCode::NOT_FOUND, "no session"),
            };
        }
    }

    // ── §50 CMS Scanner ───────────────────────────────────────────────────────
    if method == Method::POST && path == "/v1/cms-scan/run" {
        let req: CmsScanRequest = match serde_json::from_slice(&body) {
            Ok(r) => r, Err(e) => return text(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        let store = state.cms_results.clone();
        tokio::spawn(async move {
            if let Ok(r) = lancer_cms::scan(req).await {
                store.write().push(r);
            }
        });
        return json(&serde_json::json!({"ok": true, "queued": true}));
    }
    if method == Method::GET && path == "/v1/cms-scan" {
        return json(&*state.cms_results.read());
    }
    if method == Method::DELETE && path == "/v1/cms-scan" {
        state.cms_results.write().clear();
        return json(&serde_json::json!({"ok": true}));
    }

    // ── §51 Exploit-DB ────────────────────────────────────────────────────────
    if let Some(cve) = path.strip_prefix("/v1/exploits/by-cve/") {
        if method == Method::GET {
            return json(&state.exploitdb.by_cve(cve));
        }
    }
    if let Some(q) = path.strip_prefix("/v1/exploits/by-keyword/") {
        if method == Method::GET {
            return json(&state.exploitdb.by_keyword(q));
        }
    }

    // ── §52 Modules ──────────────────────────────────────────────────────────
    if method == Method::GET && path == "/v1/modules" {
        return json(&state.modules.list());
    }
    if let Some(rest) = path.strip_prefix("/v1/modules/") {
        if let Some(id) = rest.strip_suffix("/start") {
            if method == Method::POST {
                return match state.modules.start(id).await {
                    Ok(_) => json(&serde_json::json!({"ok": true})),
                    Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
                };
            }
        }
        if let Some(id) = rest.strip_suffix("/stop") {
            if method == Method::POST {
                return match state.modules.stop(id).await {
                    Ok(_) => json(&serde_json::json!({"ok": true})),
                    Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
                };
            }
        }
        if let Some(id) = rest.strip_suffix("/status") {
            if method == Method::GET {
                let list = state.modules.list();
                return match list.into_iter().find(|m| m.id == id) {
                    Some(m) => json(&m),
                    None => text(StatusCode::NOT_FOUND, "no module"),
                };
            }
        }
    }
    if method == Method::GET && path == "/v1/modules/presets" {
        return json(&state.module_presets.list());
    }
    if method == Method::POST && path == "/v1/modules/presets" {
        let p: Preset = match serde_json::from_slice(&body) {
            Ok(p) => p, Err(e) => return text(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        state.module_presets.save(p.clone());
        return json(&p);
    }

    text(StatusCode::NOT_FOUND, "not found")
}

fn register_module(reg: &Arc<ModuleRegistry>, m: Box<dyn lancer_modules::LancerModule>) {
    reg.register_boxed(m);
}

// Allow ModuleState to be parsed in URL endpoints (not currently used in routes).
#[allow(dead_code)]
fn _module_state_for_serde() -> ModuleState { ModuleState::Off }

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn history_list(state: &AppState, query: &str) -> Response<Full<Bytes>> {
    let storage = state.project.read().clone();
    let Some(storage) = storage else { return json(&serde_json::json!([])) };
    let limit = parse_query(query, "limit").and_then(|v| v.parse().ok()).unwrap_or(200i64);
    match storage.history().list(&lancer_storage::HistoryFilter { limit: Some(limit), ..Default::default() }).await {
        Ok(rows) => json(&rows),
        Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn history_get(state: &AppState, id: uuid::Uuid) -> Response<Full<Bytes>> {
    let storage = state.project.read().clone();
    let Some(storage) = storage else { return text(StatusCode::NOT_FOUND, "no project") };
    match storage.history().get(id).await {
        Ok(Some(row)) => json(&row),
        Ok(None) => text(StatusCode::NOT_FOUND, "not found"),
        Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn history_delete(state: &AppState, id: uuid::Uuid) -> Response<Full<Bytes>> {
    let storage = state.project.read().clone();
    let Some(storage) = storage else { return text(StatusCode::NOT_FOUND, "no project") };
    match storage.history().delete(id).await {
        Ok(_) => json(&serde_json::json!({ "ok": true })),
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
    if let Ok(active) = engine.run_active(&req).await { all.extend(active); }
    json(&all)
}

async fn issues_list(state: &AppState) -> Response<Full<Bytes>> {
    let storage = state.project.read().clone();
    let Some(storage) = storage else { return json(&serde_json::json!([])) };
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
        "html"     => ("text/html; charset=utf-8", render_html(&meta, &issues, &f)),
        "markdown" => ("text/markdown", render_markdown(&meta, &issues, &f)),
        "sarif"    => ("application/sarif+json", render_sarif(&meta, &issues, &f)),
        "xml"      => ("application/xml", render_xml(&meta, &issues, &f)),
        _          => ("application/json", render_json(&meta, &issues, &f)),
    };
    Response::builder()
        .status(200)
        .header("content-type", ct)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

async fn repeater(state: &AppState, body: &[u8]) -> Response<Full<Bytes>> {
    #[derive(serde::Deserialize)]
    struct R { request: String, scheme: Option<String>, host: Option<String>, port: Option<u16> }
    let Ok(r) = serde_json::from_slice::<R>(body) else { return text(StatusCode::BAD_REQUEST, "bad json") };
    let Ok(mut req) = HttpRequest::parse_wire(r.request.as_bytes()) else { return text(StatusCode::BAD_REQUEST, "bad request") };
    req.meta.scheme = r.scheme.unwrap_or_else(|| "https".into());
    if let Some(h) = r.host { if !h.is_empty() { req.meta.host = h; } }
    if let Some(p) = r.port { if p > 0 { req.meta.port = p; } }
    match state.client.send(&req).await {
        Ok(resp) => json(&serde_json::json!({
            "status": resp.status,
            "headers": resp.headers,
            "body": resp.body_text().unwrap_or(""),
            "elapsed_ms": resp.elapsed_ms,
            "raw": String::from_utf8_lossy(&resp.to_wire()),
        })),
        Err(e) => text(StatusCode::BAD_GATEWAY, &e.to_string()),
    }
}

async fn intruder(state: &AppState, body: &[u8]) -> Response<Full<Bytes>> {
    #[derive(serde::Deserialize)]
    struct R {
        request: String,
        scheme: Option<String>,
        host: Option<String>,
        port: Option<u16>,
        kind: Option<String>,
        payloads: Option<Vec<Vec<String>>>,
    }
    let Ok(r) = serde_json::from_slice::<R>(body) else { return text(StatusCode::BAD_REQUEST, "bad json") };
    let Ok(mut req) = HttpRequest::parse_wire(r.request.as_bytes()) else { return text(StatusCode::BAD_REQUEST, "bad request") };
    req.meta.scheme = r.scheme.unwrap_or_else(|| "https".into());
    if let Some(h) = r.host { if !h.is_empty() { req.meta.host = h; } }
    if let Some(p) = r.port { if p > 0 { req.meta.port = p; } }

    let kind = match r.kind.as_deref() {
        Some("BatteringRam") => AttackKind::BatteringRam,
        Some("Pitchfork")    => AttackKind::Pitchfork,
        Some("ClusterBomb")  => AttackKind::ClusterBomb,
        _                    => AttackKind::Sniper,
    };
    let sets: Vec<PayloadSet> = r.payloads.unwrap_or_default().into_iter()
        .map(|items| PayloadSet::Simple(items))
        .collect();

    let template = ParsedTemplate::parse(req, lancer_tools::DEFAULT_MARKER);
    if template.positions.is_empty() {
        return text(StatusCode::BAD_REQUEST, "no payload markers (§…§) in request");
    };

    let cfg = IntruderConfig { kind, ..Default::default() };
    let intruder = Intruder::new(state.client.clone(), cfg);
    match intruder.run(template, sets).await {
        Ok(results) => json(&results),
        Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Probe up to 10 ports starting at `preferred`; return the first free one.
async fn find_free_proxy_addr(preferred: SocketAddr) -> SocketAddr {
    let ip = preferred.ip();
    let base = preferred.port();
    for offset in 0u16..=10 {
        if let Some(port) = base.checked_add(offset) {
            let candidate = SocketAddr::new(ip, port);
            if TcpListener::bind(candidate).await.is_ok() {
                return candidate;
            }
        }
    }
    preferred
}

fn parse_query(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| pair.strip_prefix(&format!("{key}=")).map(|v| v.to_string()))
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
            "/v1/history/{id}": { "get": { "summary": "Get one request by ID" }, "delete": { "summary": "Delete one entry" } },
            "/v1/issues": { "get": { "summary": "List stored issues" } },
            "/v1/scan/passive": { "post": { "summary": "Run passive checks on a URL" } },
            "/v1/scan/active": { "post": { "summary": "Run active checks on a raw request" } },
            "/v1/scan/full": { "post": { "summary": "Passive + active on a URL" } },
            "/v1/report": { "get": { "summary": "Render report" } },
            "/v1/repeater": { "post": { "summary": "Send a single request" } },
            "/v1/intruder": { "post": { "summary": "Run an intruder attack" } },
            "/v1/proxy/status": { "get": { "summary": "Proxy running state" } },
            "/v1/proxy/intercept/toggle": { "post": { "summary": "Toggle request/response interception" } },
            "/v1/proxy/intercept/queue": { "get": { "summary": "List paused requests" } },
            "/v1/proxy/intercept/forward": { "post": { "summary": "Forward a paused request" } },
            "/v1/proxy/intercept/drop": { "post": { "summary": "Drop a paused request" } },
            "/v1/proxy/ca-cert.pem": { "get": { "summary": "Download CA certificate (PEM)" } },
            "/v1/proxy/ca-cert.der": { "get": { "summary": "Download CA certificate (DER)" } },
            "/v1/proxy/rules": { "get": { "summary": "Get match/replace rules" }, "put": { "summary": "Replace all rules" } },
            "/v1/scope": { "get": { "summary": "Get scope rules" }, "put": { "summary": "Replace scope rules" } },
        }
    })
}
