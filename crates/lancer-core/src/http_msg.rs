//! HTTP message types used throughout Lancer.
//!
//! These are *owned* in-memory representations independent of any specific HTTP
//! stack. The proxy converts to/from `hyper` types at the edge; everything
//! downstream (history, repeater, intruder, scanner) operates on these.

use std::fmt;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};

/// Globally unique identifier for a stored HTTP message or pair.
pub type MessageId = Uuid;

/// HTTP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpVersion {
    Http09,
    Http10,
    Http11,
    Http2,
    Http3,
}

impl HttpVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            HttpVersion::Http09 => "HTTP/0.9",
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
            HttpVersion::Http2 => "HTTP/2",
            HttpVersion::Http3 => "HTTP/3",
        }
    }
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a captured message is a request or response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction {
    Request,
    Response,
}

/// A small wrapper around `http::Method` that is serializable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SerializableMethod(pub String);

impl SerializableMethod {
    pub fn get() -> Self {
        Self("GET".into())
    }
    pub fn post() -> Self {
        Self("POST".into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for SerializableMethod {
    fn from(s: &str) -> Self {
        Self(s.to_ascii_uppercase())
    }
}

impl fmt::Display for SerializableMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Coarse-grained body classification used for filtering and rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MimeKind {
    Html,
    Json,
    Xml,
    JavaScript,
    Css,
    Text,
    Image,
    Font,
    Binary,
    Multipart,
    FormUrlEncoded,
    GraphQL,
    Unknown,
}

impl MimeKind {
    pub fn from_content_type(ct: &str) -> Self {
        let ct = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        match ct.as_str() {
            "text/html" | "application/xhtml+xml" => MimeKind::Html,
            "application/json" | "application/manifest+json" => MimeKind::Json,
            "application/xml" | "text/xml" => MimeKind::Xml,
            "application/javascript" | "text/javascript" => MimeKind::JavaScript,
            "text/css" => MimeKind::Css,
            "text/plain" => MimeKind::Text,
            "application/x-www-form-urlencoded" => MimeKind::FormUrlEncoded,
            "application/graphql" => MimeKind::GraphQL,
            x if x.starts_with("image/") => MimeKind::Image,
            x if x.starts_with("font/") => MimeKind::Font,
            x if x.starts_with("multipart/") => MimeKind::Multipart,
            x if x.starts_with("text/") => MimeKind::Text,
            "" => MimeKind::Unknown,
            _ => MimeKind::Binary,
        }
    }
}

/// Common metadata attached to every captured message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMeta {
    pub id: MessageId,
    /// When the message was received/sent by the proxy.
    pub captured_at: DateTime<Utc>,
    /// Host the message was associated with (`Host:` header for requests,
    /// derived for responses).
    pub host: String,
    /// Port (default derived from scheme).
    pub port: u16,
    /// Scheme (`http` / `https` / `ws` / `wss`).
    pub scheme: String,
    /// `true` if the source was a tool like Repeater, `false` if from the proxy.
    pub tool_generated: bool,
    /// Optional comment for the History UI.
    pub comment: Option<String>,
    /// Optional 1-byte color tag.
    pub color: Option<String>,
}

impl MessageMeta {
    pub fn new(host: impl Into<String>, scheme: impl Into<String>, port: u16) -> Self {
        Self {
            id: Uuid::new_v4(),
            captured_at: Utc::now(),
            host: host.into(),
            port,
            scheme: scheme.into(),
            tool_generated: false,
            comment: None,
            color: None,
        }
    }
}

/// A name/value HTTP header pair. We keep insertion order and allow duplicates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

impl Header {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self { name: name.into(), value: value.into() }
    }
}

/// An owned HTTP request representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub meta: MessageMeta,
    pub method: SerializableMethod,
    pub path: String,
    pub version: HttpVersion,
    pub headers: Vec<Header>,
    #[serde(with = "bytes_serde")]
    pub body: Bytes,
}

impl HttpRequest {
    pub fn builder(method: impl Into<SerializableMethod>, url: &str) -> Result<Self> {
        let parsed = url::Url::parse(url)?;
        let host = parsed.host_str().ok_or_else(|| Error::parse("url missing host"))?;
        let scheme = parsed.scheme();
        let port = parsed.port_or_known_default().unwrap_or_else(|| match scheme {
            "https" => 443,
            _ => 80,
        });
        let mut path = parsed.path().to_string();
        if let Some(q) = parsed.query() {
            path.push('?');
            path.push_str(q);
        }
        if path.is_empty() {
            path.push('/');
        }
        Ok(HttpRequest {
            meta: MessageMeta::new(host, scheme, port),
            method: method.into(),
            path,
            version: HttpVersion::Http11,
            headers: vec![Header::new("Host", host)],
            body: Bytes::new(),
        })
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    pub fn set_header(&mut self, name: &str, value: impl Into<String>) {
        let value = value.into();
        if let Some(h) = self.headers.iter_mut().find(|h| h.name.eq_ignore_ascii_case(name)) {
            h.value = value;
        } else {
            self.headers.push(Header::new(name, value));
        }
    }

    pub fn remove_header(&mut self, name: &str) {
        self.headers.retain(|h| !h.name.eq_ignore_ascii_case(name));
    }

    /// Reconstruct the absolute URL for routing.
    pub fn url(&self) -> String {
        format!("{}://{}{}", self.meta.scheme, self.host_with_port(), self.path)
    }

    pub fn host_with_port(&self) -> String {
        let default_port = matches!(
            (self.meta.scheme.as_str(), self.meta.port),
            ("http", 80) | ("https", 443)
        );
        if default_port {
            self.meta.host.clone()
        } else {
            format!("{}:{}", self.meta.host, self.meta.port)
        }
    }

    pub fn body_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.body).ok()
    }

    /// Serialize the request to its on-the-wire HTTP/1.1 form.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.body.len());
        out.extend_from_slice(self.method.as_str().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.path.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.version.as_str().as_bytes());
        out.extend_from_slice(b"\r\n");
        for h in &self.headers {
            out.extend_from_slice(h.name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(h.value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    /// Parse a wire-format HTTP/1.x request. Useful for the Repeater raw editor.
    pub fn parse_wire(input: &[u8]) -> Result<Self> {
        let mut headers_buf = [httparse::EMPTY_HEADER; 128];
        let mut req = httparse::Request::new(&mut headers_buf);
        let status = req.parse(input).map_err(|e| Error::parse(format!("httparse: {e}")))?;
        let body_start = match status {
            httparse::Status::Complete(n) => n,
            httparse::Status::Partial => return Err(Error::parse("incomplete request")),
        };
        let method = req.method.ok_or_else(|| Error::parse("missing method"))?;
        let path = req.path.ok_or_else(|| Error::parse("missing path"))?;
        let version = match req.version {
            Some(0) => HttpVersion::Http10,
            Some(1) => HttpVersion::Http11,
            _ => HttpVersion::Http11,
        };

        let mut host = String::new();
        let mut headers_vec = Vec::with_capacity(req.headers.len());
        for h in req.headers.iter() {
            let name = h.name.to_string();
            let value = std::str::from_utf8(h.value)
                .map_err(|_| Error::parse("non-utf8 header value"))?
                .to_string();
            if name.eq_ignore_ascii_case("Host") {
                host = value.clone();
            }
            headers_vec.push(Header { name, value });
        }
        let (host_only, port) = split_host_port(&host, 80);
        Ok(HttpRequest {
            meta: MessageMeta::new(host_only, "http", port),
            method: SerializableMethod(method.to_string()),
            path: path.to_string(),
            version,
            headers: headers_vec,
            body: Bytes::copy_from_slice(&input[body_start..]),
        })
    }
}

/// An owned HTTP response representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub meta: MessageMeta,
    pub status: u16,
    pub reason: String,
    pub version: HttpVersion,
    pub headers: Vec<Header>,
    #[serde(with = "bytes_serde")]
    pub body: Bytes,
    pub elapsed_ms: Option<u64>,
}

impl HttpResponse {
    pub fn new(status: u16) -> Self {
        Self {
            meta: MessageMeta::new("", "http", 80),
            status,
            reason: default_reason(status).to_string(),
            version: HttpVersion::Http11,
            headers: Vec::new(),
            body: Bytes::new(),
            elapsed_ms: None,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    pub fn set_header(&mut self, name: &str, value: impl Into<String>) {
        let value = value.into();
        if let Some(h) = self.headers.iter_mut().find(|h| h.name.eq_ignore_ascii_case(name)) {
            h.value = value;
        } else {
            self.headers.push(Header::new(name, value));
        }
    }

    pub fn remove_header(&mut self, name: &str) {
        self.headers.retain(|h| !h.name.eq_ignore_ascii_case(name));
    }

    pub fn mime(&self) -> MimeKind {
        self.header("Content-Type")
            .map(MimeKind::from_content_type)
            .unwrap_or(MimeKind::Unknown)
    }

    pub fn body_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.body).ok()
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.body.len());
        out.extend_from_slice(self.version.as_str().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.status.to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.reason.as_bytes());
        out.extend_from_slice(b"\r\n");
        for h in &self.headers {
            out.extend_from_slice(h.name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(h.value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    pub fn parse_wire(input: &[u8]) -> Result<Self> {
        let mut headers_buf = [httparse::EMPTY_HEADER; 128];
        let mut resp = httparse::Response::new(&mut headers_buf);
        let status = resp.parse(input).map_err(|e| Error::parse(format!("httparse: {e}")))?;
        let body_start = match status {
            httparse::Status::Complete(n) => n,
            httparse::Status::Partial => return Err(Error::parse("incomplete response")),
        };
        let code = resp.code.ok_or_else(|| Error::parse("missing status"))?;
        let reason = resp.reason.unwrap_or("").to_string();
        let version = match resp.version {
            Some(0) => HttpVersion::Http10,
            Some(1) => HttpVersion::Http11,
            _ => HttpVersion::Http11,
        };
        let mut headers_vec = Vec::with_capacity(resp.headers.len());
        for h in resp.headers.iter() {
            let value = std::str::from_utf8(h.value)
                .map_err(|_| Error::parse("non-utf8 header value"))?
                .to_string();
            headers_vec.push(Header { name: h.name.to_string(), value });
        }
        Ok(HttpResponse {
            meta: MessageMeta::new("", "http", 80),
            status: code,
            reason,
            version,
            headers: headers_vec,
            body: Bytes::copy_from_slice(&input[body_start..]),
            elapsed_ms: None,
        })
    }
}

fn split_host_port(s: &str, default_port: u16) -> (String, u16) {
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (s.to_string(), default_port)
}

fn default_reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        418 => "I'm a teapot",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

mod bytes_serde {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &Bytes, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_bytes(value.as_ref())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Bytes, D::Error> {
        let v: Vec<u8> = Vec::deserialize(de)?;
        Ok(Bytes::from(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let mut req = HttpRequest::builder("GET", "https://example.com/api?x=1").unwrap();
        req.set_header("User-Agent", "lancer-test");
        let wire = req.to_wire();
        let s = String::from_utf8(wire).unwrap();
        assert!(s.starts_with("GET /api?x=1 HTTP/1.1"));
        assert!(s.contains("Host: example.com"));
        assert!(s.contains("User-Agent: lancer-test"));
    }

    #[test]
    fn parse_wire_request() {
        let wire = b"POST /login HTTP/1.1\r\nHost: example.com:8080\r\nContent-Length: 5\r\n\r\nhello";
        let req = HttpRequest::parse_wire(wire).unwrap();
        assert_eq!(req.method.as_str(), "POST");
        assert_eq!(req.path, "/login");
        assert_eq!(req.meta.host, "example.com");
        assert_eq!(req.meta.port, 8080);
        assert_eq!(req.body.as_ref(), b"hello");
    }

    #[test]
    fn response_roundtrip() {
        let mut resp = HttpResponse::new(200);
        resp.set_header("Content-Type", "text/plain");
        resp.body = Bytes::from_static(b"ok");
        let wire = resp.to_wire();
        let parsed = HttpResponse::parse_wire(&wire).unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body.as_ref(), b"ok");
    }

    #[test]
    fn mime_classify() {
        assert_eq!(MimeKind::from_content_type("application/json"), MimeKind::Json);
        assert_eq!(MimeKind::from_content_type("text/html; charset=utf-8"), MimeKind::Html);
        assert_eq!(MimeKind::from_content_type("image/png"), MimeKind::Image);
        assert_eq!(MimeKind::from_content_type(""), MimeKind::Unknown);
    }
}
