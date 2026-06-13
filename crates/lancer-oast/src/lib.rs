//! Out-of-band application security testing (OAST) server.
//!
//! This is Lancer's self-hosted equivalent of the Burp Collaborator. A single
//! [`OastServer`] owns three optional listeners:
//!
//! - **DNS** (UDP): answers `A` queries for `*.<domain>` and records every
//!   lookup. This catches blind SSRF / blind RCE / deserialization callbacks
//!   that only resolve a hostname (the most common OOB signal).
//! - **HTTP** (TCP): records any request whose `Host` correlates to a payload
//!   and replies `200 OK`.
//! - **SMTP** (TCP): minimal ESMTP conversation; records the envelope when a
//!   `RCPT TO` address correlates to a payload (catches mail-based exfil).
//!
//! Each [`allocate`](OastServer::allocate) hands out `<id>.<domain>`. When an
//! interaction arrives the [correlation engine](OastServer::correlate) maps the
//! hostname back to the payload `id` that planted it, so a scanner / Repeater /
//! Intruder hit can be tied to the exact request that triggered it.
//!
//! All listeners default to **high, unprivileged ports** (DNS 5353, HTTP 8088,
//! SMTP 1825) so the server starts without root; point real `*.<domain>` NS /
//! A records (or a port-forward) at the machine for a public deployment.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use uuid::Uuid;

// ── Data model ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InteractionKind {
    Dns,
    Http,
    Smtp,
}

/// A single recorded out-of-band hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interaction {
    pub id: Uuid,
    pub kind: InteractionKind,
    /// The payload label this hit correlated back to (empty if uncorrelated).
    pub payload_id: String,
    pub remote_ip: Option<String>,
    pub timestamp: DateTime<Utc>,
    /// The full hostname / recipient / path that triggered the hit.
    pub query: String,
    /// Protocol-specific detail (DNS qtype, HTTP method+headers, SMTP envelope).
    pub raw: serde_json::Value,
}

/// A planted payload handed to a tool to inject into a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocatedPayload {
    pub id: String,
    pub host: String,
    pub created_at: DateTime<Utc>,
}

/// Server configuration. Cloneable snapshot read by listeners at start time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OastConfig {
    pub domain: String,
    pub bind_ip: IpAddr,
    pub dns_port: u16,
    pub http_port: u16,
    pub smtp_port: u16,
    /// `A` record handed back to DNS clients (point this at the public IP).
    pub answer_ip: Ipv4Addr,
    pub enable_dns: bool,
    pub enable_http: bool,
    pub enable_smtp: bool,
}

impl Default for OastConfig {
    fn default() -> Self {
        Self {
            domain: "oast.lancer.local".into(),
            bind_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dns_port: 5353,
            http_port: 8088,
            smtp_port: 1825,
            answer_ip: Ipv4Addr::new(127, 0, 0, 1),
            enable_dns: true,
            enable_http: true,
            enable_smtp: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OastStatus {
    pub running: bool,
    pub domain: String,
    pub dns: Option<u16>,
    pub http: Option<u16>,
    pub smtp: Option<u16>,
    pub interaction_count: usize,
    pub payload_count: usize,
}

// ── Store ───────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Store {
    interactions: Vec<Interaction>,
    payloads: HashMap<String, AllocatedPayload>,
}

// ── Server ──────────────────────────────────────────────────────────────────

pub struct OastServer {
    config: RwLock<OastConfig>,
    store: RwLock<Store>,
    handles: Mutex<Vec<JoinHandle<()>>>,
    running: AtomicBool,
}

impl OastServer {
    pub fn new(config: OastConfig) -> Arc<Self> {
        Arc::new(Self {
            config: RwLock::new(config),
            store: RwLock::new(Store::default()),
            handles: Mutex::new(Vec::new()),
            running: AtomicBool::new(false),
        })
    }

    pub fn with_defaults() -> Arc<Self> {
        Self::new(OastConfig::default())
    }

    pub fn config(&self) -> OastConfig {
        self.config.read().clone()
    }

    pub fn set_config(&self, config: OastConfig) {
        *self.config.write() = config;
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Allocate a fresh `<id>.<domain>` payload and register it for correlation.
    pub fn allocate(&self) -> AllocatedPayload {
        let id = Uuid::new_v4().simple().to_string();
        let domain = self.config.read().domain.clone();
        let payload = AllocatedPayload {
            id: id.clone(),
            host: format!("{id}.{domain}"),
            created_at: Utc::now(),
        };
        self.store.write().payloads.insert(id, payload.clone());
        payload
    }

    /// Map a hostname / recipient back to a registered payload id, if any.
    ///
    /// Strips the configured `domain` suffix, then walks the remaining labels
    /// right-to-left returning the first that matches a registered payload.
    pub fn correlate(&self, name: &str) -> Option<String> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let store = self.store.read();
        let domain = self.config.read().domain.to_ascii_lowercase();
        let prefix = name.strip_suffix(&format!(".{domain}")).unwrap_or(&name);
        for label in prefix.rsplit('.') {
            if store.payloads.contains_key(label) {
                return Some(label.to_string());
            }
        }
        None
    }

    fn record(
        &self,
        kind: InteractionKind,
        query: String,
        remote_ip: Option<String>,
        raw: serde_json::Value,
    ) {
        let payload_id = self.correlate(&query).unwrap_or_default();
        let interaction = Interaction {
            id: Uuid::new_v4(),
            kind,
            payload_id,
            remote_ip,
            timestamp: Utc::now(),
            query,
            raw,
        };
        let mut store = self.store.write();
        store.interactions.push(interaction);
        // Cap memory: keep the most recent 10k interactions.
        let len = store.interactions.len();
        if len > 10_000 {
            store.interactions.drain(0..len - 10_000);
        }
    }

    pub fn interactions(&self) -> Vec<Interaction> {
        self.store.read().interactions.clone()
    }

    /// Interactions strictly after `since` (for incremental polling).
    pub fn poll_since(&self, since: Option<DateTime<Utc>>) -> Vec<Interaction> {
        let store = self.store.read();
        match since {
            Some(t) => store
                .interactions
                .iter()
                .filter(|i| i.timestamp > t)
                .cloned()
                .collect(),
            None => store.interactions.clone(),
        }
    }

    pub fn payloads(&self) -> Vec<AllocatedPayload> {
        self.store.read().payloads.values().cloned().collect()
    }

    pub fn clear(&self) {
        self.store.write().interactions.clear();
    }

    pub fn status(&self) -> OastStatus {
        let cfg = self.config.read();
        let running = self.is_running();
        let store = self.store.read();
        OastStatus {
            running,
            domain: cfg.domain.clone(),
            dns: (running && cfg.enable_dns).then_some(cfg.dns_port),
            http: (running && cfg.enable_http).then_some(cfg.http_port),
            smtp: (running && cfg.enable_smtp).then_some(cfg.smtp_port),
            interaction_count: store.interactions.len(),
            payload_count: store.payloads.len(),
        }
    }

    /// Start every enabled listener. Idempotent — a no-op while already running.
    ///
    /// Binds all sockets before taking the handle lock so no non-`Send` guard is
    /// held across an `.await` (which would make the future un-spawnable).
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        if self.is_running() {
            return Ok(());
        }
        let cfg = self.config.read().clone();
        let mut new_handles: Vec<JoinHandle<()>> = Vec::new();

        let bind: Result<()> = async {
            if cfg.enable_dns {
                let sock = UdpSocket::bind(SocketAddr::new(cfg.bind_ip, cfg.dns_port)).await?;
                let server = self.clone();
                let answer = cfg.answer_ip;
                new_handles.push(tokio::spawn(async move { dns_loop(server, sock, answer).await }));
                tracing::info!("oast: DNS listener on {}:{}", cfg.bind_ip, cfg.dns_port);
            }
            if cfg.enable_http {
                let listener = TcpListener::bind(SocketAddr::new(cfg.bind_ip, cfg.http_port)).await?;
                let server = self.clone();
                new_handles.push(tokio::spawn(async move { http_loop(server, listener).await }));
                tracing::info!("oast: HTTP listener on {}:{}", cfg.bind_ip, cfg.http_port);
            }
            if cfg.enable_smtp {
                let listener = TcpListener::bind(SocketAddr::new(cfg.bind_ip, cfg.smtp_port)).await?;
                let server = self.clone();
                new_handles.push(tokio::spawn(async move { smtp_loop(server, listener).await }));
                tracing::info!("oast: SMTP listener on {}:{}", cfg.bind_ip, cfg.smtp_port);
            }
            Ok(())
        }
        .await;

        match bind {
            Ok(()) => {
                self.handles.lock().extend(new_handles);
                self.running.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(e) => {
                for h in new_handles {
                    h.abort();
                }
                Err(e)
            }
        }
    }

    /// Stop all listeners. Allocated payloads + recorded interactions survive.
    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }
        for h in self.handles.lock().drain(..) {
            h.abort();
        }
    }
}

// ── DNS listener ────────────────────────────────────────────────────────────

async fn dns_loop(server: Arc<OastServer>, sock: UdpSocket, answer: Ipv4Addr) {
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("oast dns recv error: {e}");
                continue;
            }
        };
        let packet = &buf[..n];
        let Some((qname, qtype)) = parse_dns_question(packet) else {
            continue;
        };
        server.record(
            InteractionKind::Dns,
            qname.clone(),
            Some(peer.ip().to_string()),
            serde_json::json!({ "qtype": qtype, "qname": qname }),
        );
        if let Some(reply) = build_dns_reply(packet, qtype, answer) {
            let _ = sock.send_to(&reply, peer).await;
        }
    }
}

/// Parse the first question of a DNS query: returns (qname, qtype).
fn parse_dns_question(packet: &[u8]) -> Option<(String, u16)> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut idx = 12;
    let mut labels = Vec::new();
    loop {
        if idx >= packet.len() {
            return None;
        }
        let len = packet[idx] as usize;
        idx += 1;
        if len == 0 {
            break;
        }
        // Compression pointers shouldn't appear in a question; bail if so.
        if len & 0xC0 != 0 {
            return None;
        }
        if idx + len > packet.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&packet[idx..idx + len]).to_string());
        idx += len;
    }
    if idx + 4 > packet.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[idx], packet[idx + 1]]);
    Some((labels.join("."), qtype))
}

/// Build a minimal DNS response. Answers `A` (qtype 1) with `answer`; for any
/// other qtype returns an answer-less NOERROR response (records still happen).
fn build_dns_reply(query: &[u8], qtype: u16, answer: Ipv4Addr) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    // Find end of the question section to copy it verbatim.
    let mut idx = 12;
    loop {
        if idx >= query.len() {
            return None;
        }
        let len = query[idx] as usize;
        idx += 1;
        if len == 0 {
            break;
        }
        idx += len;
    }
    idx += 4; // qtype + qclass
    if idx > query.len() {
        return None;
    }
    let question = &query[12..idx];

    let mut out = Vec::with_capacity(idx + 16);
    out.extend_from_slice(&query[0..2]); // transaction id
    out.extend_from_slice(&[0x81, 0x80]); // flags: response, recursion available
    out.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    let ancount: u16 = if qtype == 1 { 1 } else { 0 };
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    out.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    out.extend_from_slice(question);

    if qtype == 1 {
        out.extend_from_slice(&[0xC0, 0x0C]); // name pointer to the question
        out.extend_from_slice(&[0x00, 0x01]); // type A
        out.extend_from_slice(&[0x00, 0x01]); // class IN
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x1E]); // TTL 30s
        out.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
        out.extend_from_slice(&answer.octets());
    }
    Some(out)
}

// ── HTTP listener ───────────────────────────────────────────────────────────

async fn http_loop(server: Arc<OastServer>, listener: TcpListener) {
    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("oast http accept error: {e}");
                continue;
            }
        };
        let server = server.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            let n = match stream.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };
            let raw = String::from_utf8_lossy(&buf[..n]).to_string();
            let (method, path, host, headers) = parse_http_head(&raw);
            let query = if host.is_empty() { path.clone() } else { host.clone() };
            server.record(
                InteractionKind::Http,
                query,
                Some(peer.ip().to_string()),
                serde_json::json!({
                    "method": method,
                    "path": path,
                    "host": host,
                    "headers": headers,
                }),
            );
            let body = b"ok";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nServer: lancer-oast\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.write_all(body).await;
            let _ = stream.shutdown().await;
        });
    }
}

fn parse_http_head(raw: &str) -> (String, String, String, Vec<String>) {
    let mut lines = raw.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let mut host = String::new();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("host:") {
            host = rest.trim().to_string();
        }
        headers.push(line.to_string());
    }
    (method, path, host, headers)
}

// ── SMTP listener ───────────────────────────────────────────────────────────

async fn smtp_loop(server: Arc<OastServer>, listener: TcpListener) {
    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("oast smtp accept error: {e}");
                continue;
            }
        };
        let server = server.clone();
        tokio::spawn(async move {
            let _ = stream.write_all(b"220 lancer-oast ESMTP ready\r\n").await;
            let mut buf = vec![0u8; 8 * 1024];
            let mut recipients: Vec<String> = Vec::new();
            let mut mail_from = String::new();
            let mut in_data = false;
            let mut data = String::new();
            loop {
                let n = match stream.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => break,
                };
                let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                if in_data {
                    data.push_str(&chunk);
                    if data.contains("\r\n.\r\n") {
                        let _ = stream.write_all(b"250 OK queued\r\n").await;
                        in_data = false;
                    }
                    continue;
                }
                for line in chunk.split("\r\n") {
                    if line.is_empty() {
                        continue;
                    }
                    let upper = line.to_ascii_uppercase();
                    if upper.starts_with("HELO") || upper.starts_with("EHLO") {
                        let _ = stream.write_all(b"250 lancer-oast\r\n").await;
                    } else if upper.starts_with("MAIL FROM") {
                        mail_from = line.to_string();
                        let _ = stream.write_all(b"250 OK\r\n").await;
                    } else if upper.starts_with("RCPT TO") {
                        recipients.push(line.to_string());
                        let _ = stream.write_all(b"250 OK\r\n").await;
                    } else if upper.starts_with("DATA") {
                        in_data = true;
                        let _ = stream.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n").await;
                    } else if upper.starts_with("QUIT") {
                        let _ = stream.write_all(b"221 Bye\r\n").await;
                    } else {
                        let _ = stream.write_all(b"250 OK\r\n").await;
                    }
                }
            }
            // Correlate via the first recipient address (which carries the host).
            let query = recipients
                .iter()
                .find_map(|r| r.split('@').nth(1).map(|h| h.trim_end_matches(['>', ' ']).to_string()))
                .unwrap_or_default();
            server.record(
                InteractionKind::Smtp,
                query,
                Some(peer.ip().to_string()),
                serde_json::json!({
                    "mail_from": mail_from,
                    "recipients": recipients,
                    "data": data,
                }),
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_and_correlate() {
        let s = OastServer::with_defaults();
        let p = s.allocate();
        assert!(p.host.ends_with(".oast.lancer.local"));
        // Direct hostname.
        assert_eq!(s.correlate(&p.host).as_deref(), Some(p.id.as_str()));
        // Attacker-prepended labels still correlate.
        let prepended = format!("whoami.{}", p.host);
        assert_eq!(s.correlate(&prepended).as_deref(), Some(p.id.as_str()));
        // Unknown host does not.
        assert_eq!(s.correlate("nope.oast.lancer.local"), None);
    }

    #[test]
    fn dns_question_roundtrip() {
        // id=0x1234, flags, qd=1; question "a.b" type A class IN
        let packet = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, b'a',
            0x01, b'b', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let (qname, qtype) = parse_dns_question(&packet).unwrap();
        assert_eq!(qname, "a.b");
        assert_eq!(qtype, 1);
        let reply = build_dns_reply(&packet, qtype, Ipv4Addr::new(1, 2, 3, 4)).unwrap();
        assert_eq!(&reply[0..2], &[0x12, 0x34]);
        assert_eq!(&reply[6..8], &[0x00, 0x01]); // ANCOUNT 1
        assert_eq!(&reply[reply.len() - 4..], &[1, 2, 3, 4]);
    }
}
