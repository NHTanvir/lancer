//! Collaborator — out-of-band attack detection.
//!
//! In Burp, the Collaborator is a hosted server with DNS / HTTP / SMTP
//! listeners; checks plant unique subdomains and later poll for hits. We ship
//! a pluggable trait + a built-in stub that always returns "no interactions",
//! plus a real HTTP-poll client for self-hosted collaborator servers.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InteractionKind {
    Dns,
    Http,
    Smtp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interaction {
    pub id: Uuid,
    pub kind: InteractionKind,
    pub remote_ip: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub payload_id: String,
    pub raw: serde_json::Value,
}

#[async_trait]
pub trait Collaborator: Send + Sync {
    /// Allocate a unique payload identifier and return the full hostname an
    /// attacker would inject into a request (e.g. `<id>.lancer-oob.example.net`).
    fn allocate(&self) -> AllocatedPayload;

    /// Poll for any interactions that have occurred since the last call.
    async fn poll(&self) -> Result<Vec<Interaction>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocatedPayload {
    pub id: String,
    pub host: String,
}

/// Noop implementation used when out-of-band testing is disabled.
pub struct NoopCollaborator;

#[async_trait]
impl Collaborator for NoopCollaborator {
    fn allocate(&self) -> AllocatedPayload {
        let id = Uuid::new_v4().simple().to_string();
        AllocatedPayload { id: id.clone(), host: format!("{id}.lancer.local") }
    }
    async fn poll(&self) -> Result<Vec<Interaction>> {
        Ok(Vec::new())
    }
}

/// Self-hosted HTTP collaborator client. Polls `<base>/interactions?since=...`
/// and parses a JSON array of interactions.
pub struct HttpCollaborator {
    pub base_url: String,
    pub domain: String,
    pub client: lancer_tools::HttpClient,
    state: Arc<parking_lot::RwLock<HttpState>>,
}

#[derive(Default)]
struct HttpState {
    last_poll: Option<DateTime<Utc>>,
}

impl HttpCollaborator {
    pub fn new(base_url: String, domain: String) -> Self {
        Self {
            base_url,
            domain,
            client: lancer_tools::HttpClient::new(),
            state: Arc::new(parking_lot::RwLock::new(HttpState::default())),
        }
    }
}

#[async_trait]
impl Collaborator for HttpCollaborator {
    fn allocate(&self) -> AllocatedPayload {
        let id = Uuid::new_v4().simple().to_string();
        AllocatedPayload { id: id.clone(), host: format!("{id}.{}", self.domain) }
    }

    async fn poll(&self) -> Result<Vec<Interaction>> {
        let since = self.state.read().last_poll;
        let url = match since {
            Some(t) => format!("{}/interactions?since={}", self.base_url, t.to_rfc3339()),
            None => format!("{}/interactions", self.base_url),
        };
        let cursor = Utc::now(); // capture BEFORE sending so no interaction can slip between windows
        let req = lancer_core::HttpRequest::builder("GET", &url)?;
        let resp = self.client.send(&req).await?;
        if !(200..300).contains(&resp.status) {
            anyhow::bail!("collaborator returned {}", resp.status);
        }
        let body = resp.body_text().unwrap_or("[]");
        let items: Vec<Interaction> = serde_json::from_str(body)?;
        self.state.write().last_poll = Some(cursor);
        Ok(items)
    }
}
