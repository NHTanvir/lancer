//! WebSocket framing helpers + the §1.3 MITM upgrade tunnel.
//!
//! Decodes frame headers so we can log message size, opcode, and direction,
//! and provides `handle_websocket_upgrade` which proxies a WebSocket through the
//! intercepting proxy while transparently forwarding raw bytes and persisting
//! every decoded frame to the `WsStore`.

use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::{Buf, Bytes, BytesMut};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use lancer_storage::websocket::{WsDirection, WsFrameType, WsMessage, WsStore};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use crate::mitm::PipelineHandles;
use crate::settings::ProxySettings;
use crate::upstream;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Opcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Reserved,
}

impl Opcode {
    fn from_u8(v: u8) -> Self {
        match v {
            0x0 => Opcode::Continuation,
            0x1 => Opcode::Text,
            0x2 => Opcode::Binary,
            0x8 => Opcode::Close,
            0x9 => Opcode::Ping,
            0xA => Opcode::Pong,
            _ => Opcode::Reserved,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FrameHeader {
    pub fin: bool,
    pub opcode: Opcode,
    pub masked: bool,
    pub payload_len: usize,
    pub header_len: usize,
    pub mask_key: Option<[u8; 4]>,
}

impl FrameHeader {
    /// Try to parse the header in `buf`. Returns `Ok(None)` if more bytes are
    /// needed, `Err` on malformed input.
    pub fn parse(buf: &[u8]) -> Result<Option<FrameHeader>, &'static str> {
        if buf.len() < 2 {
            return Ok(None);
        }
        let b0 = buf[0];
        let fin = b0 & 0x80 != 0;
        let opcode = Opcode::from_u8(b0 & 0x0F);
        let b1 = buf[1];
        let masked = b1 & 0x80 != 0;
        let len7 = (b1 & 0x7F) as usize;
        let mut idx = 2;
        let payload_len = match len7 {
            126 => {
                if buf.len() < idx + 2 {
                    return Ok(None);
                }
                let v = u16::from_be_bytes([buf[idx], buf[idx + 1]]) as usize;
                idx += 2;
                v
            }
            127 => {
                if buf.len() < idx + 8 {
                    return Ok(None);
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&buf[idx..idx + 8]);
                idx += 8;
                u64::from_be_bytes(arr) as usize
            }
            n => n,
        };
        let mask_key = if masked {
            if buf.len() < idx + 4 {
                return Ok(None);
            }
            let mut k = [0u8; 4];
            k.copy_from_slice(&buf[idx..idx + 4]);
            idx += 4;
            Some(k)
        } else {
            None
        };
        Ok(Some(FrameHeader {
            fin,
            opcode,
            masked,
            payload_len,
            header_len: idx,
            mask_key,
        }))
    }

    pub fn apply_mask(&self, payload: &mut [u8]) {
        if let Some(key) = self.mask_key {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= key[i % 4];
            }
        }
    }
}

type BoxIo = Box<dyn AsyncReadWrite + Send + Unpin>;

/// Marker for a duplex stream usable for the origin connection.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

#[allow(clippy::too_many_arguments)]
pub async fn handle_websocket_upgrade(
    mut req: Request<Incoming>,
    scheme: &str,
    host: String,
    port: u16,
    pipeline: PipelineHandles,
    tls_client_config: Arc<ClientConfig>,
    settings: Arc<ProxySettings>,
    dns: Arc<crate::dns::DnsTable>,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    // Capture the client-side upgrade future before consuming the request.
    let client_up = hyper::upgrade::on(&mut req);
    let (parts, _body) = req.into_parts();

    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let url = format!(
        "{}://{}{}",
        if scheme == "https" { "wss" } else { "ws" },
        host,
        path
    );

    // Reconstruct the handshake request for the origin (pass headers through).
    let mut head = format!("{} {} HTTP/1.1\r\n", parts.method, path);
    for (k, v) in parts.headers.iter() {
        if let Ok(vs) = v.to_str() {
            head.push_str(&format!("{}: {}\r\n", k.as_str(), vs));
        }
    }
    head.push_str("\r\n");

    // Dial origin (TLS for wss).
    let stream = upstream::dial(&host, port, settings.upstream_for(&host), Some(&dns)).await?;
    let mut origin: BoxIo = if scheme == "https" {
        let connector = TlsConnector::from(tls_client_config.clone());
        let sni = ServerName::try_from(host.clone()).context("invalid SNI for ws origin")?;
        Box::new(connector.connect(sni, stream).await?)
    } else {
        Box::new(stream)
    };

    // Send the handshake, read the 101 response head, keep any trailing bytes.
    origin.write_all(head.as_bytes()).await?;
    let (resp_head, leftover) = read_http_head(&mut origin).await?;
    let (status, resp_headers) = parse_response_head(&resp_head);
    if status != 101 {
        // Not switching protocols — relay the status so the client sees it.
        return Ok(Response::builder()
            .status(status)
            .body(Full::new(Bytes::from(resp_head.into_bytes())))?);
    }

    // Build the 101 response to return to the client (mirroring origin headers).
    let mut builder = Response::builder().status(101);
    for (k, v) in &resp_headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let client_resp = builder.body(Full::new(Bytes::new()))?;

    // After hyper sends the 101, run the bidirectional frame-capturing tunnel.
    let ws_store = pipeline.ws_store.clone();
    tokio::spawn(async move {
        let upgraded = match client_up.await {
            Ok(u) => u,
            Err(e) => {
                tracing::debug!("ws client upgrade failed: {e}");
                return;
            }
        };
        let client = TokioIo::new(upgraded);
        if let Err(e) = tunnel(client, origin, leftover, ws_store, host, url).await {
            tracing::debug!("ws tunnel ended: {e}");
        }
    });

    Ok(client_resp)
}

/// Read bytes until the end of an HTTP head (`\r\n\r\n`); return (head, trailing).
async fn read_http_head<R: AsyncRead + Unpin>(r: &mut R) -> Result<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = r.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 64 * 1024 {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf).to_string();
    Ok((head, Vec::new()))
}

fn parse_response_head(head: &str) -> (u16, Vec<(String, String)>) {
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect();
    (status, headers)
}

fn frame_type(op: Opcode) -> Option<WsFrameType> {
    match op {
        Opcode::Text => Some(WsFrameType::Text),
        Opcode::Binary => Some(WsFrameType::Binary),
        Opcode::Ping => Some(WsFrameType::Ping),
        Opcode::Pong => Some(WsFrameType::Pong),
        Opcode::Close => Some(WsFrameType::Close),
        _ => None,
    }
}

/// Bidirectional copy: transparently forward raw bytes both ways while decoding
/// and persisting each WebSocket frame to the store.
async fn tunnel(
    client: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    origin: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    origin_leftover: Vec<u8>,
    store: Option<WsStore>,
    host: String,
    url: String,
) -> Result<()> {
    let (cr, cw) = tokio::io::split(client);
    let (or_, ow) = tokio::io::split(origin);

    let c2s = pump(cr, ow, Vec::new(), store.clone(), host.clone(), url.clone(), WsDirection::ClientToServer);
    let s2c = pump(or_, cw, origin_leftover, store, host, url, WsDirection::ServerToClient);
    let _ = tokio::join!(c2s, s2c);
    Ok(())
}

async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
    prefill: Vec<u8>,
    store: Option<WsStore>,
    host: String,
    url: String,
    direction: WsDirection,
) {
    let mut decode = BytesMut::new();
    if !prefill.is_empty() {
        // Forward the bytes already read past the handshake, then decode them.
        let _ = w.write_all(&prefill).await;
        decode.extend_from_slice(&prefill);
        drain_and_store(&mut decode, &store, &host, &url, direction).await;
    }
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
        decode.extend_from_slice(&buf[..n]);
        drain_and_store(&mut decode, &store, &host, &url, direction).await;
    }
    let _ = w.shutdown().await;
}

async fn drain_and_store(
    decode: &mut BytesMut,
    store: &Option<WsStore>,
    host: &str,
    url: &str,
    direction: WsDirection,
) {
    while let Ok(Some((header, payload))) = drain_frame(decode) {
        let Some(ft) = frame_type(header.opcode) else { continue };
        if let Some(s) = store {
            let msg = WsMessage {
                id: uuid::Uuid::new_v4(),
                captured_at: chrono::Utc::now(),
                host: host.to_string(),
                url: url.to_string(),
                direction,
                frame_type: ft,
                payload,
                comment: None,
            };
            let _ = s.insert(&msg).await;
        }
    }
}

/// Strip one frame from `buf` if a complete one is present.
pub fn drain_frame(buf: &mut BytesMut) -> Result<Option<(FrameHeader, Vec<u8>)>, &'static str> {
    let Some(header) = FrameHeader::parse(buf)? else {
        return Ok(None);
    };
    let total = header.header_len + header.payload_len;
    if buf.len() < total {
        return Ok(None);
    }
    buf.advance(header.header_len);
    let mut payload = buf.split_to(header.payload_len).to_vec();
    header.apply_mask(&mut payload);
    Ok(Some((header, payload)))
}
