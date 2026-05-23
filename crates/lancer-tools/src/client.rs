//! Async HTTP client used by Repeater, Intruder, and Scanner.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use lancer_core::{HttpRequest, HttpResponse, MessageMeta};

#[derive(Clone)]
pub struct HttpClient {
    inner: Client<HttpsConnector, Full<Bytes>>,
    timeout: Duration,
}

pub type HttpsConnector = hyper_util::client::legacy::connect::HttpConnector;

impl HttpClient {
    pub fn new() -> Self {
        let mut connector = HttpsConnector::new();
        connector.enforce_http(false);
        let inner = Client::builder(TokioExecutor::new()).build(connector);
        Self { inner, timeout: Duration::from_secs(30) }
    }

    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    pub async fn send(&self, req: &HttpRequest) -> Result<HttpResponse> {
        let mut builder = http::Request::builder()
            .method(req.method.as_str())
            .uri(req.url())
            .version(http::Version::HTTP_11);
        for h in &req.headers {
            if h.name.eq_ignore_ascii_case("host") {
                continue;
            }
            builder = builder.header(h.name.as_str(), h.value.as_str());
        }
        let hyper_req = builder
            .body(Full::new(req.body.clone()))
            .context("building outbound request")?;

        let started = Instant::now();
        let resp = tokio::time::timeout(self.timeout, self.inner.request(hyper_req))
            .await
            .context("client timeout")??;
        let (parts, body) = resp.into_parts();
        let collected = body.collect().await.context("collect body")?;
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
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
pub(crate) fn _arc_marker() -> Arc<()> {
    Arc::new(())
}
