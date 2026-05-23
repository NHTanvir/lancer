//! Async HTTP/HTTPS client used by Repeater, Intruder, and the Scanner.
//!
//! Implemented as a small connect-per-request wrapper around `hyper`'s
//! HTTP/1.1 client. Good enough for the tools — the proxy keeps its own,
//! pooled hyper connections.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use http_body_util::{BodyExt as _, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use lancer_core::{HttpRequest, HttpResponse, MessageMeta};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Clone)]
pub struct HttpClient {
    timeout: Duration,
    tls: Arc<ClientConfig>,
}

impl HttpClient {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            tls: build_client_tls(),
        }
    }

    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    pub async fn send(&self, req: &HttpRequest) -> Result<HttpResponse> {
        let stream = TcpStream::connect((req.meta.host.as_str(), req.meta.port))
            .await
            .with_context(|| format!("connect {}:{}", req.meta.host, req.meta.port))?;
        let started = Instant::now();

        let resp = if req.meta.scheme == "https" {
            let dns = ServerName::try_from(req.meta.host.clone())?;
            let tls_stream = TlsConnector::from(self.tls.clone())
                .connect(dns, stream)
                .await
                .context("client TLS")?;
            self.send_inner(req, TokioIo::new(tls_stream)).await?
        } else {
            self.send_inner(req, TokioIo::new(stream)).await?
        };

        let (parts, body) = resp.into_parts();
        let collected = body.collect().await.context("body")?;
        let bytes = collected.to_bytes();
        let mut headers = Vec::with_capacity(parts.headers.len());
        for (n, v) in parts.headers.iter() {
            headers.push(lancer_core::http_msg::Header {
                name: n.as_str().to_string(),
                value: v.to_str().unwrap_or("").to_string(),
            });
        }
        let mut meta = MessageMeta::new(&req.meta.host, &req.meta.scheme, req.meta.port);
        meta.tool_generated = true;
        Ok(HttpResponse {
            meta,
            status: parts.status.as_u16(),
            reason: parts.status.canonical_reason().unwrap_or("").to_string(),
            version: lancer_core::HttpVersion::Http11,
            headers,
            body: bytes,
            elapsed_ms: Some(started.elapsed().as_millis() as u64),
        })
    }

    async fn send_inner<T>(
        &self,
        req: &HttpRequest,
        io: TokioIo<T>,
    ) -> Result<hyper::Response<hyper::body::Incoming>>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("client conn closed: {e}");
            }
        });
        let mut builder = Request::builder()
            .method(req.method.as_str())
            .uri(&req.path)
            .version(http::Version::HTTP_11);
        let mut saw_host = false;
        for h in &req.headers {
            if h.name.eq_ignore_ascii_case("host") {
                saw_host = true;
            }
            builder = builder.header(h.name.as_str(), h.value.as_str());
        }
        if !saw_host {
            builder = builder.header("Host", req.host_with_port());
        }
        let hyper_req = builder.body(Full::new(req.body.clone()))?;
        let resp = tokio::time::timeout(self.timeout, sender.send_request(hyper_req))
            .await
            .context("timeout")??;
        Ok(resp)
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

fn build_client_tls() -> Arc<ClientConfig> {
    use rustls::pki_types::TrustAnchor;
    let mut roots = rustls::RootCertStore::empty();
    let anchors: Vec<TrustAnchor<'static>> = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    roots.roots.extend(anchors);
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}
