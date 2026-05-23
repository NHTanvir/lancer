//! Proxy listener settings.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::dns::DnsOverride;
use crate::platform_auth::AuthCredential;

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
    /// Default upstream proxy applied to anything not matched by a rule below.
    pub upstream: Option<UpstreamProxy>,
    /// Host-pattern-specific upstream rules. First match wins.
    pub upstream_rules: Vec<UpstreamRule>,
    /// Stored credentials for Basic/Digest/NTLM/Negotiate auth.
    pub platform_auth: Vec<AuthCredential>,
    /// Hostname-resolution overrides (DNS-over-Lancer).
    pub dns_overrides: Vec<DnsOverride>,
    /// Client-side TLS cert (PEM-encoded) used when the upstream demands mTLS.
    pub client_tls: Vec<ClientTlsCert>,
    pub max_in_flight: usize,
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub ca_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamRule {
    pub host_pattern: String,
    pub upstream: UpstreamProxy,
}

impl UpstreamRule {
    pub fn matches(&self, host: &str) -> bool {
        if let Some(rest) = self.host_pattern.strip_prefix("*.") {
            host == rest || host.ends_with(&format!(".{rest}"))
        } else {
            host.eq_ignore_ascii_case(&self.host_pattern)
        }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientTlsCert {
    pub host_pattern: String,
    pub cert_pem_path: PathBuf,
    pub key_pem_path: PathBuf,
}

impl ClientTlsCert {
    pub fn matches(&self, host: &str) -> bool {
        if let Some(rest) = self.host_pattern.strip_prefix("*.") {
            host == rest || host.ends_with(&format!(".{rest}"))
        } else {
            host.eq_ignore_ascii_case(&self.host_pattern)
        }
    }
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
            upstream_rules: Vec::new(),
            platform_auth: Vec::new(),
            dns_overrides: Vec::new(),
            client_tls: Vec::new(),
            max_in_flight: 1024,
            connect_timeout_ms: 15_000,
            read_timeout_ms: 60_000,
            ca_dir: PathBuf::from("./ca"),
        }
    }
}

impl ProxySettings {
    /// Resolve the appropriate upstream proxy for the given target host.
    pub fn upstream_for(&self, host: &str) -> Option<&UpstreamProxy> {
        for r in &self.upstream_rules {
            if r.matches(host) {
                return Some(&r.upstream);
            }
        }
        self.upstream.as_ref()
    }

    pub fn client_tls_for(&self, host: &str) -> Option<&ClientTlsCert> {
        self.client_tls.iter().find(|c| c.matches(host))
    }

    pub fn platform_auth_for(&self, host: &str) -> Option<&AuthCredential> {
        self.platform_auth.iter().find(|a| a.matches(host))
    }
}
