//! Dual-session replay engine.
//!
//! Replays a single request under two session identities (e.g. a high-privilege
//! "victim" session and a low-privilege "attacker" session) and compares the
//! two responses. If the low-privilege session receives the same resource as
//! the high-privilege one, that is a strong broken-access-control / IDOR signal.

use anyhow::Result;
use lancer_core::HttpRequest;
use lancer_tools::HttpClient;
use serde::{Deserialize, Serialize};

/// One session's credentials, applied to the request before replay.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionCreds {
    #[serde(default)]
    pub name: String,
    /// Full `Cookie:` header value (overwrites the request's cookie).
    #[serde(default)]
    pub cookie: Option<String>,
    /// Full `Authorization:` header value.
    #[serde(default)]
    pub authorization: Option<String>,
    /// Any extra headers to set/override.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResp {
    pub session: String,
    pub status: u16,
    pub length: usize,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualReplayResult {
    pub a: ReplayResp,
    pub b: ReplayResp,
    /// 0.0–1.0 body similarity between the two responses.
    pub similarity: f64,
    /// Human-readable access-control verdict.
    pub verdict: String,
    /// True when session B appears to improperly reach the same resource.
    pub access_control_issue: bool,
}

fn apply(base: &HttpRequest, creds: &SessionCreds) -> HttpRequest {
    let mut req = base.clone();
    if let Some(c) = &creds.cookie {
        req.set_header("cookie", c.clone());
    }
    if let Some(a) = &creds.authorization {
        req.set_header("authorization", a.clone());
    }
    for (k, v) in &creds.headers {
        if !k.is_empty() {
            req.set_header(k, v.clone());
        }
    }
    req
}

async fn replay(client: &HttpClient, req: &HttpRequest, name: &str) -> ReplayResp {
    match client.send(req).await {
        Ok(resp) => ReplayResp {
            session: name.to_string(),
            status: resp.status,
            length: resp.body.len(),
            body: resp.body_text().unwrap_or("").to_string(),
            headers: resp.headers.iter().map(|h| (h.name.clone(), h.value.clone())).collect(),
        },
        Err(e) => ReplayResp {
            session: name.to_string(),
            status: 0,
            length: 0,
            body: format!("(request error: {e})"),
            headers: Vec::new(),
        },
    }
}

pub async fn dual_replay(
    client: &HttpClient,
    base: &HttpRequest,
    a: &SessionCreds,
    b: &SessionCreds,
) -> Result<DualReplayResult> {
    let name_a = if a.name.is_empty() { "Session A".to_string() } else { a.name.clone() };
    let name_b = if b.name.is_empty() { "Session B".to_string() } else { b.name.clone() };

    let ra = replay(client, &apply(base, a), &name_a).await;
    let rb = replay(client, &apply(base, b), &name_b).await;
    let similarity = crate::token_similarity(&ra.body, &rb.body);

    // Verdict: A is the authorised baseline; B is the lower-privilege session.
    let (verdict, issue) = if rb.status == 401 || rb.status == 403 {
        (format!("{name_b} was correctly denied ({}). Access control looks enforced.", rb.status), false)
    } else if ra.status == 200 && rb.status == 200 && similarity >= 0.9 {
        (format!(
            "⚠ {name_b} received the same resource as {name_a} ({:.0}% identical). \
             Possible broken access control / IDOR — the resource is not scoped to the session.",
            similarity * 100.0
        ), true)
    } else if ra.status == 200 && rb.status == 200 {
        (format!(
            "Both sessions got 200 but bodies differ ({:.0}% similar) — likely per-session data; review manually.",
            similarity * 100.0
        ), false)
    } else {
        (format!("{name_a} → {}, {name_b} → {}. Review the difference.", ra.status, rb.status), false)
    };

    Ok(DualReplayResult { a: ra, b: rb, similarity, verdict, access_control_issue: issue })
}
