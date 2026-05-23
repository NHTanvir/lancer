//! Forwarding pipeline used after a `CONNECT host:443` has been MITM'd.
//!
//! Once the listener has terminated TLS using a freshly-minted leaf cert, this
//! module sees plaintext HTTP/1.1 (and, when ALPN allows, HTTP/2 via hyper).
//! Each captured request goes through:
//! 1. match-and-replace (request)
//! 2. scope check
//! 3. intercept engine
//! 4. forward upstream
//! 5. match-and-replace (response)
//! 6. intercept engine (response)
//! 7. history persistence
//! 8. forward back to client

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use bytes::Bytes;
use lancer_core::{HttpRequest, HttpResponse, HttpVersion, MessageMeta, SerializableMethod};
use lancer_storage::HistoryStore;
use tracing::warn;

use crate::events::{ProxyEvent, ProxyEventSink};
use crate::intercept::{InterceptDecision, InterceptEngine};
use crate::match_replace::MatchReplaceEngine;

#[derive(Debug, Clone)]
pub struct PipelineContext {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub in_scope: bool,
}

#[derive(Debug, Clone)]
pub struct PipelineHandles {
    pub intercept: InterceptEngine,
    pub match_replace: MatchReplaceEngine,
    pub history: Option<HistoryStore>,
    pub events: ProxyEventSink,
}

impl PipelineHandles {
    /// Process a captured `HttpRequest` and prepare it for outbound dispatch.
    /// Returns `Ok(None)` if the engine decided to drop.
    pub async fn process_request(
        &self,
        mut req: HttpRequest,
        ctx: &PipelineContext,
    ) -> Result<Option<HttpRequest>> {
        // 1. ensure meta is consistent with the connection context
        req.meta.scheme = ctx.scheme.clone();
        if req.meta.host.is_empty() {
            req.meta.host = ctx.host.clone();
        }
        if req.meta.port == 0 {
            req.meta.port = ctx.port;
        }

        // 2. match & replace
        let hits = self.match_replace.apply_request(&mut req, ctx.in_scope);
        if hits > 0 {
            tracing::debug!(hits, "applied request match/replace");
        }

        // 3. intercept
        match self.intercept.decide_request(&req) {
            InterceptDecision::Forward => {}
            InterceptDecision::Drop => return Ok(None),
            InterceptDecision::Pause => {
                self.events
                    .emit(ProxyEvent::InterceptionPaused { id: req.meta.id })
                    .await;
            }
        }

        // 4. history insert (request-only row, response attached later)
        if let Some(h) = &self.history {
            if let Err(e) = h.insert_request(&req, ctx.in_scope).await {
                warn!("failed to insert history row: {e}");
            }
        }

        self.events
            .emit(ProxyEvent::RequestCaptured {
                id: req.meta.id,
                request: req.clone(),
                in_scope: ctx.in_scope,
            })
            .await;

        Ok(Some(req))
    }

    pub async fn process_response(
        &self,
        request_id: uuid::Uuid,
        mut resp: HttpResponse,
        ctx: &PipelineContext,
    ) -> Result<Option<HttpResponse>> {
        let _ = self.match_replace.apply_response(&mut resp, ctx.in_scope);
        match self.intercept.decide_response(&resp) {
            InterceptDecision::Forward => {}
            InterceptDecision::Drop => return Ok(None),
            InterceptDecision::Pause => {
                self.events
                    .emit(ProxyEvent::InterceptionPaused { id: resp.meta.id })
                    .await;
            }
        }
        if let Some(h) = &self.history {
            if let Err(e) = h.attach_response(request_id, &resp).await {
                warn!("failed to attach response: {e}");
            }
        }
        self.events
            .emit(ProxyEvent::ResponseCaptured {
                id: resp.meta.id,
                response: resp.clone(),
            })
            .await;
        Ok(Some(resp))
    }
}

/// Convert a `hyper::Request` to our owned `HttpRequest`, draining the body.
pub async fn hyper_request_to_owned<B>(
    parts: http::request::Parts,
    body: B,
    scheme: &str,
    default_host: &str,
    default_port: u16,
) -> Result<HttpRequest>
where
    B: http_body::Body + Unpin,
    B::Error: std::fmt::Display,
{
    use http_body_util::BodyExt as _;
    let collected = body
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("body read: {e}"))?;
    let bytes = collected.to_bytes();
    let host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| default_host.to_string());
    let (host_only, port) = split_host_port(&host, default_port);
    let mut headers = Vec::with_capacity(parts.headers.len());
    for (n, v) in parts.headers.iter() {
        headers.push(lancer_core::http_msg::Header {
            name: n.as_str().to_string(),
            value: v.to_str().unwrap_or("").to_string(),
        });
    }
    let version = match parts.version {
        http::Version::HTTP_10 => HttpVersion::Http10,
        http::Version::HTTP_11 => HttpVersion::Http11,
        http::Version::HTTP_2 => HttpVersion::Http2,
        http::Version::HTTP_3 => HttpVersion::Http3,
        _ => HttpVersion::Http11,
    };
    let meta = MessageMeta::new(host_only, scheme, port);
    Ok(HttpRequest {
        meta,
        method: SerializableMethod(parts.method.as_str().to_string()),
        path: parts
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string()),
        version,
        headers,
        body: bytes,
    })
}

pub async fn hyper_response_to_owned<B>(
    parts: http::response::Parts,
    body: B,
) -> Result<HttpResponse>
where
    B: http_body::Body + Unpin,
    B::Error: std::fmt::Display,
{
    use http_body_util::BodyExt as _;
    let collected = body
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("body read: {e}"))?;
    let bytes = collected.to_bytes();
    let mut headers = Vec::with_capacity(parts.headers.len());
    for (n, v) in parts.headers.iter() {
        headers.push(lancer_core::http_msg::Header {
            name: n.as_str().to_string(),
            value: v.to_str().unwrap_or("").to_string(),
        });
    }
    let version = match parts.version {
        http::Version::HTTP_10 => HttpVersion::Http10,
        http::Version::HTTP_11 => HttpVersion::Http11,
        http::Version::HTTP_2 => HttpVersion::Http2,
        http::Version::HTTP_3 => HttpVersion::Http3,
        _ => HttpVersion::Http11,
    };
    let mut meta = MessageMeta::new("", "http", 80);
    meta.captured_at = chrono::Utc::now();
    Ok(HttpResponse {
        meta,
        status: parts.status.as_u16(),
        reason: parts.status.canonical_reason().unwrap_or("").to_string(),
        version,
        headers,
        body: bytes,
        elapsed_ms: None,
    })
}

/// Convert our owned `HttpRequest` back into a `hyper::Request<Bytes>`
/// for outbound dispatch.
pub fn owned_request_to_hyper(req: &HttpRequest) -> Result<http::Request<Bytes>> {
    let mut builder = http::Request::builder()
        .method(req.method.as_str())
        .uri(req.path.as_str())
        .version(match req.version {
            HttpVersion::Http10 => http::Version::HTTP_10,
            HttpVersion::Http2 => http::Version::HTTP_2,
            _ => http::Version::HTTP_11,
        });
    for h in &req.headers {
        if h.name.eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        builder = builder.header(h.name.as_str(), h.value.as_str());
    }
    Ok(builder.body(req.body.clone())?)
}

fn split_host_port(s: &str, default_port: u16) -> (String, u16) {
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (s.to_string(), default_port)
}

#[allow(dead_code)]
pub fn now_ms_since(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

#[allow(dead_code)]
pub(crate) fn detach_body(_body_bytes: Bytes) -> Arc<()> {
    Arc::new(())
}
