//! Shared core types used across every Lancer crate.
//!
//! Keep this crate dependency-light: it is pulled in by the proxy, the tools,
//! the scanner, and the CLI. Anything heavy (networking, TLS, SQLite, GUI) lives
//! elsewhere.

pub mod error;
pub mod http_msg;
pub mod inspector;
pub mod project;
pub mod scope;
pub mod sitemap;
pub mod transform;
pub mod workspace;

pub use error::{Error, Result};
pub use http_msg::{
    Direction, HttpRequest, HttpResponse, HttpVersion, MessageId, MessageMeta, MimeKind,
    SerializableMethod,
};
pub use inspector::{Inspector, Param, ParamLocation};
pub use project::{Project, ProjectKind, ProjectMeta};
pub use scope::{Scope, ScopeMatch, ScopeRule, ScopeRuleKind};
