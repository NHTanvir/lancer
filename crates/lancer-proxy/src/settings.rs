//! Proxy listener settings.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerBind {
    pub addr: SocketAddr,
    pub transparent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySettings {
    pub listeners: Vec<ListenerBind>,
    /// Hosts to TLS-pass-through (don't MITM).
    pub tls_passthrough: Vec<String>,
    /// Upstream HTTP/SOCKS proxy.
    pub upstream: Option<UpstreamProxy>,
    pub max_in_flight: usize,
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub ca_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamProxy {
    pub kind: UpstreamKind,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpstreamKind {
    Http,
    Socks4,
    Socks5,
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            listeners: vec![ListenerBind {
                addr: "127.0.0.1:8080".parse().unwrap(),
                transparent: false,
            }],
            tls_passthrough: Vec::new(),
            upstream: None,
            max_in_flight: 1024,
            connect_timeout_ms: 15_000,
            read_timeout_ms: 60_000,
            ca_dir: PathBuf::from("./ca"),
        }
    }
}
