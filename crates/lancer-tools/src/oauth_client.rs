//! OAuth2 Client Credentials flow — detect from an OpenAPI 3.x spec and
//! transparently fetch + refresh access tokens for API scans.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use lancer_core::HttpRequest;
use parking_lot::RwLock;
use serde::Deserialize;
use serde_yaml::Value;

use crate::client::HttpClient;

#[derive(Debug, Clone)]
pub struct ClientCredentials {
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub scope: Option<String>,
}

#[derive(Default)]
struct Cached {
    token: Option<String>,
    expires_at: Option<Instant>,
}

#[derive(Clone)]
pub struct ClientCredentialsRefresher {
    pub creds: ClientCredentials,
    pub client: HttpClient,
    state: Arc<RwLock<Cached>>,
}

#[derive(Deserialize)]
struct TokenResp {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

impl ClientCredentialsRefresher {
    pub fn new(creds: ClientCredentials) -> Self {
        Self {
            creds,
            client: HttpClient::new(),
            state: Arc::new(RwLock::new(Cached::default())),
        }
    }

    pub async fn token(&self) -> Result<String> {
        if let Some(cached) = self.cached_valid() {
            return Ok(cached);
        }
        self.fetch_new().await
    }

    fn cached_valid(&self) -> Option<String> {
        let s = self.state.read();
        match (&s.token, s.expires_at) {
            (Some(t), Some(exp)) if exp > Instant::now() + Duration::from_secs(30) => {
                Some(t.clone())
            }
            _ => None,
        }
    }

    async fn fetch_new(&self) -> Result<String> {
        let body = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}{}",
            urlencode(&self.creds.client_id),
            urlencode(&self.creds.client_secret),
            self.creds
                .scope
                .as_ref()
                .map(|s| format!("&scope={}", urlencode(s)))
                .unwrap_or_default(),
        );
        let mut req = HttpRequest::builder("POST", &self.creds.token_url)?;
        req.set_header("Content-Type", "application/x-www-form-urlencoded");
        req.body = Bytes::from(body);
        let resp = self.client.send(&req).await?;
        let parsed: TokenResp = serde_json::from_slice(&resp.body)?;
        let ttl = Duration::from_secs(parsed.expires_in.unwrap_or(3600));
        let mut s = self.state.write();
        s.token = Some(parsed.access_token.clone());
        s.expires_at = Some(Instant::now() + ttl);
        Ok(parsed.access_token)
    }
}

/// Parse `securitySchemes` from an OpenAPI 3.x spec and pick the first
/// `oauth2` scheme with a `clientCredentials` flow. Returns the token URL.
pub fn detect_client_credentials(openapi_body: &str) -> Result<Option<String>> {
    let doc: Value = serde_yaml::from_str(openapi_body)?;
    let schemes = doc
        .get("components")
        .and_then(|c| c.get("securitySchemes"))
        .and_then(|s| s.as_mapping());
    let Some(schemes) = schemes else { return Ok(None) };
    for (_, scheme) in schemes {
        let kind = scheme.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if !kind.eq_ignore_ascii_case("oauth2") {
            continue;
        }
        if let Some(flows) = scheme.get("flows").and_then(|f| f.as_mapping()) {
            for (name, flow) in flows {
                if name.as_str().unwrap_or("").eq_ignore_ascii_case("clientCredentials") {
                    if let Some(token_url) = flow.get("tokenUrl").and_then(|v| v.as_str()) {
                        return Ok(Some(token_url.to_string()));
                    }
                }
            }
        }
    }
    Ok(None)
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[allow(dead_code)]
fn _unused() -> Result<()> {
    Err(anyhow!("placeholder"))
}
