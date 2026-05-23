//! TLS-MITM intercepting proxy.
//!
//! Responsibilities:
//! - bind one or more listener sockets
//! - upgrade plaintext `CONNECT host:443` to MITM with a per-host generated cert
//! - forward HTTP/1.1 + HTTP/2 (HTTP/3 planned)
//! - run the interception engine + match-and-replace pipeline
//! - emit captured request/response pairs to the storage layer
//! - support an upstream proxy (HTTP, SOCKS5)
//!
//! The listener does not concern itself with the UI; it speaks to subscribers
//! through an async event channel.

pub mod browser;
pub mod ca;
pub mod ca_import;
pub mod cert_cache;
pub mod events;
pub mod intercept;
pub mod listener;
pub mod match_replace;
pub mod mitm;
pub mod dns;
pub mod platform_auth;
pub mod settings;
pub mod sse;
pub mod upstream;
pub mod websocket;

pub use ca::{CertificateAuthority, CaConfig};
pub use cert_cache::CertCache;
pub use events::{ProxyEvent, ProxyEventSink};
pub use intercept::{InterceptDecision, InterceptEngine, InterceptRule};
pub use listener::ProxyListener;
pub use match_replace::{MatchReplaceEngine, MatchReplaceRule, MatchTarget};
pub use settings::ProxySettings;
