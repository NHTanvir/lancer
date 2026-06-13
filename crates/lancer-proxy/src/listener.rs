//! The actual TCP listener.
//!
//! Lifecycle of a single connection:
//! 1. accept TCP
//! 2. peek first line — if `CONNECT host:port`, do MITM handshake; else treat
//!    as a forward-proxy HTTP/1.1 request
//! 3. for MITM:
//!    a. respond `200 Connection established`
//!    b. accept TLS from client using a leaf cert we just minted
//!    c. dial outbound (direct or via upstream proxy) and do TLS to origin
//!    d. shuttle requests via hyper
//! 4. for forward-proxy (plain HTTP):
//!    a. parse hyper request
//!    b. dial outbound
//!    c. proxy and capture

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use lancer_core::scope::Scope;
use lancer_core::HttpRequest;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, error, info, warn};

use crate::ca::CertificateAuthority;
use crate::cert_cache::CertCache;
use crate::events::{ProxyEvent, ProxyEventSink};
use crate::intercept::InterceptEngine;
use crate::intercept_queue::InterceptPauseQueue;
use crate::match_replace::MatchReplaceEngine;
use crate::mitm::{
    hyper_request_to_owned, hyper_response_to_owned, owned_request_to_hyper, PipelineContext,
    PipelineHandles,
};
use crate::settings::ProxySettings;
use crate::upstream;

pub struct ProxyListener {
    pub settings: Arc<ProxySettings>,
    pub ca: Arc<CertificateAuthority>,
    pub cert_cache: Arc<CertCache>,
    pub intercept: InterceptEngine,
    pub match_replace: MatchReplaceEngine,
    pub scope: Arc<parking_lot::RwLock<Scope>>,
    pub history: Option<lancer_storage::HistoryStore>,
    pub events: ProxyEventSink,
    pub tls_client_config: Arc<ClientConfig>,
    pub dns: Arc<crate::dns::DnsTable>,
    pub intercept_pause: Option<Arc<InterceptPauseQueue>>,
    /// §17 in-flight session-handling rule application (optional).
    pub session_apply: Option<Arc<dyn Fn(&mut HttpRequest) + Send + Sync>>,
    /// §1.3 WebSocket frame capture store (optional).
    pub ws_store: Option<lancer_storage::websocket::WsStore>,
}

impl ProxyListener {
    pub fn new(
        settings: Arc<ProxySettings>,
        ca: Arc<CertificateAuthority>,
        intercept: InterceptEngine,
        match_replace: MatchReplaceEngine,
        scope: Arc<parking_lot::RwLock<Scope>>,
        history: Option<lancer_storage::HistoryStore>,
        events: ProxyEventSink,
        intercept_pause: Option<Arc<InterceptPauseQueue>>,
    ) -> Self {
        let cert_cache = Arc::new(CertCache::new(ca.clone()));
        let tls_client_config = build_default_client_config();
        let dns = Arc::new(crate::dns::DnsTable::new());
        dns.replace(settings.dns_overrides.clone());
        Self {
            settings,
            ca,
            cert_cache,
            intercept,
            match_replace,
            scope,
            history,
            events,
            tls_client_config,
            dns,
            intercept_pause,
            session_apply: None,
            ws_store: None,
        }
    }

    /// Attach a §17 session-handling rule applicator run on every in-flight
    /// request (sets auth headers / cookies). No-op until rules are configured.
    pub fn with_session_apply(
        mut self,
        f: Arc<dyn Fn(&mut HttpRequest) + Send + Sync>,
    ) -> Self {
        self.session_apply = Some(f);
        self
    }

    /// Attach a §1.3 WebSocket frame store; decoded frames are persisted to it.
    pub fn with_ws_store(mut self, store: lancer_storage::websocket::WsStore) -> Self {
        self.ws_store = Some(store);
        self
    }

    /// Start serving on every configured listener and run until shut down.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let mut handles = Vec::new();
        for bind in &self.settings.listeners {
            let me = self.clone();
            let addr = bind.addr;
            handles.push(tokio::spawn(async move {
                if let Err(e) = me.serve_one(addr).await {
                    error!("listener {addr} died: {e:#}");
                }
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        Ok(())
    }

    async fn serve_one(self: Arc<Self>, addr: SocketAddr) -> Result<()> {
        let l = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding {addr}"))?;
        info!("Lancer proxy listening on {addr}");
        loop {
            let (sock, peer) = match l.accept().await {
                Ok(x) => x,
                Err(e) => {
                    warn!("accept: {e}");
                    continue;
                }
            };
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.handle_connection(sock, peer).await {
                    debug!("connection {peer} ended: {e:#}");
                }
            });
        }
    }

    async fn handle_connection(self: Arc<Self>, sock: TcpStream, _peer: SocketAddr) -> Result<()> {
        let _ = sock.set_nodelay(true);
        // Peek the first chunk so we can decide CONNECT vs forward-proxy.
        let mut peek_buf = [0u8; 8];
        let n = sock.peek(&mut peek_buf).await?;
        if n >= 7 && peek_buf[..7].eq_ignore_ascii_case(b"CONNECT") {
            self.handle_connect(sock).await
        } else {
            self.handle_forward(sock).await
        }
    }

    async fn handle_connect(self: Arc<Self>, mut sock: TcpStream) -> Result<()> {
        // Read just the request line + headers; throw them away after capturing host:port.
        let mut buf = [0u8; 4096];
        let mut total = 0;
        loop {
            let n = sock.read(&mut buf[total..]).await?;
            if n == 0 {
                return Ok(());
            }
            total += n;
            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if total == buf.len() {
                return Err(anyhow::anyhow!("CONNECT too long"));
            }
        }
        let head = std::str::from_utf8(&buf[..total]).unwrap_or("");
        let target = head
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("malformed CONNECT"))?;
        let (host, port) = parse_host_port(target).context("parsing CONNECT target")?;
        debug!("CONNECT {host}:{port}");

        sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        let passthrough = self
            .settings
            .tls_passthrough
            .iter()
            .any(|h| host.eq_ignore_ascii_case(h) || matches_wildcard(h, &host));

        if passthrough {
            return self.do_tls_passthrough(sock, &host, port).await;
        }

        self.events
            .emit(ProxyEvent::ConnectionOpened {
                host: host.clone(),
                port,
                tls: true,
            })
            .await;
        self.do_mitm(sock, &host, port).await?;
        self.events
            .emit(ProxyEvent::ConnectionClosed { host, port })
            .await;
        Ok(())
    }

    /// Forward a TLS connection without intercepting (for hosts on the
    /// pass-through list, e.g. things that pin certs).
    async fn do_tls_passthrough(&self, client_sock: TcpStream, host: &str, port: u16) -> Result<()> {
        let mut upstream =
            upstream::dial(host, port, self.settings.upstream_for(host), Some(&self.dns)).await?;
        let (mut cr, mut cw) = tokio::io::split(client_sock);
        let (mut ur, mut uw) = tokio::io::split(&mut upstream);
        let c2u = tokio::io::copy(&mut cr, &mut uw);
        let u2c = tokio::io::copy(&mut ur, &mut cw);
        let _ = tokio::join!(c2u, u2c);
        Ok(())
    }

    async fn do_mitm(&self, client_sock: TcpStream, host: &str, port: u16) -> Result<()> {
        let server_cfg = self.cert_cache.server_config_for(host)?;
        let acceptor = TlsAcceptor::from(server_cfg);
        let tls = acceptor.accept(client_sock).await.context("client TLS")?;

        // hyper serves over the established TLS stream, with a per-request closure
        // that talks to the upstream origin via the TLS client config.
        let host = host.to_string();
        let pipeline = PipelineHandles {
            intercept: self.intercept.clone(),
            match_replace: self.match_replace.clone(),
            history: self.history.clone(),
            events: self.events.clone(),
            intercept_pause: self.intercept_pause.clone(),
            session_apply: self.session_apply.clone(),
            ws_store: self.ws_store.clone(),
        };
        let scope = self.scope.clone();
        let tls_client_config = self.tls_client_config.clone();
        let settings = self.settings.clone();
        let dns = self.dns.clone();
        let conn_io = TokioIo::new(tls);

        let svc = service_fn(move |req: Request<Incoming>| {
            let host = host.clone();
            let pipeline = pipeline.clone();
            let scope = scope.clone();
            let tls_client_config = tls_client_config.clone();
            let settings = settings.clone();
            let dns = dns.clone();
            async move {
                handle_mitm_request(
                    req,
                    "https",
                    host,
                    port,
                    pipeline,
                    scope,
                    tls_client_config,
                    settings,
                    dns,
                )
                .await
            }
        });

        if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection_with_upgrades(conn_io, svc)
            .await
        {
            debug!("hyper server end: {e}");
        }
        Ok(())
    }

    async fn handle_forward(self: Arc<Self>, sock: TcpStream) -> Result<()> {
        let conn_io = TokioIo::new(sock);
        let pipeline = PipelineHandles {
            intercept: self.intercept.clone(),
            match_replace: self.match_replace.clone(),
            history: self.history.clone(),
            events: self.events.clone(),
            intercept_pause: self.intercept_pause.clone(),
            session_apply: self.session_apply.clone(),
            ws_store: self.ws_store.clone(),
        };
        let scope = self.scope.clone();
        let tls_client_config = self.tls_client_config.clone();
        let settings = self.settings.clone();
        let dns = self.dns.clone();
        let svc = service_fn(move |req: Request<Incoming>| {
            let pipeline = pipeline.clone();
            let scope = scope.clone();
            let tls_client_config = tls_client_config.clone();
            let settings = settings.clone();
            let dns = dns.clone();
            async move {
                handle_forward_request(req, pipeline, scope, tls_client_config, settings, dns).await
            }
        });
        if let Err(e) = hyper::server::conn::http1::Builder::new()
            .serve_connection(conn_io, svc)
            .with_upgrades()
            .await
        {
            debug!("forward proxy conn end: {e}");
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_mitm_request(
    req: Request<Incoming>,
    scheme: &str,
    default_host: String,
    default_port: u16,
    pipeline: PipelineHandles,
    scope: Arc<parking_lot::RwLock<Scope>>,
    tls_client_config: Arc<ClientConfig>,
    settings: Arc<ProxySettings>,
    dns: Arc<crate::dns::DnsTable>,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    // §1.3 WebSocket upgrade → tunnel with frame capture (additive: only fires
    // when the client requests an Upgrade: websocket; all other traffic is HTTP).
    if is_websocket_upgrade(req.headers()) {
        return crate::websocket::handle_websocket_upgrade(
            req, scheme, default_host, default_port, pipeline, tls_client_config, settings, dns,
        )
        .await;
    }
    let (parts, body) = req.into_parts();
    let owned =
        hyper_request_to_owned(parts, body, scheme, &default_host, default_port).await?;
    dispatch(owned, pipeline, scope, tls_client_config, settings, dns).await
}

fn is_websocket_upgrade(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

async fn handle_forward_request(
    req: Request<Incoming>,
    pipeline: PipelineHandles,
    scope: Arc<parking_lot::RwLock<Scope>>,
    tls_client_config: Arc<ClientConfig>,
    settings: Arc<ProxySettings>,
    dns: Arc<crate::dns::DnsTable>,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    let (parts, body) = req.into_parts();
    // Absolute URI for forward proxy: `GET http://host/x HTTP/1.1`
    let scheme = parts
        .uri
        .scheme_str()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "http".to_string());
    let default_host = parts
        .uri
        .host()
        .map(|h| h.to_string())
        .or_else(|| {
            parts
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();
    let default_port = parts.uri.port_u16().unwrap_or(80);
    let req = Request::from_parts(parts, body);
    if is_websocket_upgrade(req.headers()) {
        return crate::websocket::handle_websocket_upgrade(
            req, &scheme, default_host, default_port, pipeline, tls_client_config, settings, dns,
        )
        .await;
    }
    let (parts, body) = req.into_parts();
    let owned =
        hyper_request_to_owned(parts, body, &scheme, &default_host, default_port).await?;
    dispatch(owned, pipeline, scope, tls_client_config, settings, dns).await
}

async fn dispatch(
    req: HttpRequest,
    pipeline: PipelineHandles,
    scope: Arc<parking_lot::RwLock<Scope>>,
    tls_client_config: Arc<ClientConfig>,
    settings: Arc<ProxySettings>,
    dns: Arc<crate::dns::DnsTable>,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    let in_scope = scope.read().is_in_scope(&req);
    let ctx = PipelineContext {
        scheme: req.meta.scheme.clone(),
        host: req.meta.host.clone(),
        port: req.meta.port,
        in_scope,
    };
    let processed = match pipeline.process_request(req.clone(), &ctx).await? {
        Some(r) => r,
        None => {
            return Ok(Response::builder()
                .status(503)
                .body(Full::new(Bytes::from_static(b"dropped by lancer\n")))?);
        }
    };

    // Outbound: open TCP/TLS to origin (or via upstream proxy) and ship request.
    let started = Instant::now();
    let stream = upstream::dial(
        &ctx.host,
        ctx.port,
        settings.upstream_for(&ctx.host),
        Some(&dns),
    )
    .await?;

    let resp = if ctx.scheme == "https" {
        let connector = TlsConnector::from(tls_client_config.clone());
        let dns = ServerName::try_from(ctx.host.clone()).context("invalid SNI")?;
        let tls = connector.connect(dns, stream).await?;
        send_via_hyper(&processed, TokioIo::new(tls)).await?
    } else {
        send_via_hyper(&processed, TokioIo::new(stream)).await?
    };
    let elapsed = started.elapsed().as_millis() as u64;

    let (resp_parts, resp_body) = resp.into_parts();
    let mut owned_resp = hyper_response_to_owned(resp_parts, resp_body).await?;
    owned_resp.meta.host = ctx.host.clone();
    owned_resp.meta.port = ctx.port;
    owned_resp.meta.scheme = ctx.scheme.clone();
    owned_resp.elapsed_ms = Some(elapsed);
    let post = pipeline
        .process_response(processed.meta.id, owned_resp.clone(), &ctx)
        .await?;
    let owned_resp = post.unwrap_or(owned_resp);

    let mut builder = Response::builder().status(owned_resp.status);
    for h in &owned_resp.headers {
        if hop_by_hop(&h.name) {
            continue;
        }
        builder = builder.header(h.name.as_str(), h.value.as_str());
    }
    Ok(builder.body(Full::new(owned_resp.body.clone()))?)
}

async fn send_via_hyper<T>(req: &HttpRequest, io: TokioIo<T>) -> Result<Response<Incoming>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("origin conn end: {e}");
        }
    });
    let hyper_req = owned_request_to_hyper(req)?;
    let resp = sender.send_request(hyper_req).await?;
    Ok(resp)
}

fn hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn parse_host_port(s: &str) -> Result<(String, u16)> {
    let (h, p) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("missing port"))?;
    Ok((h.to_string(), p.parse()?))
}

fn matches_wildcard(pattern: &str, host: &str) -> bool {
    if let Some(rest) = pattern.strip_prefix("*.") {
        return host.ends_with(rest) && host.contains('.');
    }
    pattern.eq_ignore_ascii_case(host)
}

fn build_default_client_config() -> Arc<ClientConfig> {
    use rustls::pki_types::TrustAnchor;
    let mut roots = rustls::RootCertStore::empty();
    let anchors: Vec<TrustAnchor<'static>> =
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    roots.roots.extend(anchors);
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(cfg)
}
