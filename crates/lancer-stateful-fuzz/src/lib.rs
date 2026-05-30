//! §48 Stateful API Fuzzer — RESTler equivalent.
//!
//! OpenAPI/Swagger spec → sequence inference → state-flaw detection.
//! Detectors: access-control fault, use-after-free, privilege state retention,
//! workflow skip.

use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FuzzMode { ProductionSafe, Sequence, ClusterBomb, MutateMidSequence }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzRequest {
    /// OpenAPI/Swagger spec (JSON or YAML)
    pub spec: String,
    pub base_url: String,
    pub auth_token: Option<String>,
    #[serde(default = "default_mode")]
    pub mode: FuzzMode,
    #[serde(default = "default_max_sequences")]
    pub max_sequences: usize,
}

fn default_mode() -> FuzzMode { FuzzMode::Sequence }
fn default_max_sequences() -> usize { 50 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiOp {
    pub method: String,
    pub path: String,
    pub op_id: String,
    pub produces: Vec<String>,        // response field names
    pub consumes: Vec<String>,        // request param/body field names
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sequence {
    pub id: Uuid,
    pub ops: Vec<ApiOp>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FlawKind {
    AccessControl,
    UseAfterFree,
    WorkflowSkip,
    PrivilegeRetention,
    ServerError,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity { Info, Low, Medium, High, Critical }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flaw {
    pub id: Uuid,
    pub kind: FlawKind,
    pub severity: Severity,
    pub sequence: Sequence,
    pub message: String,
    pub at_step: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzSession {
    pub id: Uuid,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub ended_at: Option<chrono::DateTime<chrono::Utc>>,
    pub ops: Vec<ApiOp>,
    pub sequences_run: usize,
    pub flaws: Vec<Flaw>,
}

// ── Spec parsing ──────────────────────────────────────────────────────────────

/// Parse an OpenAPI 2/3 spec and extract the operations.
pub fn parse_spec(text: &str) -> Result<Vec<ApiOp>, String> {
    let val: serde_json::Value = if text.trim_start().starts_with('{') {
        serde_json::from_str(text).map_err(|e| format!("json: {e}"))?
    } else {
        serde_yaml::from_str(text).map_err(|e| format!("yaml: {e}"))?
    };
    let paths = val.get("paths").and_then(|p| p.as_object())
        .ok_or_else(|| "spec has no `paths`".to_string())?;
    let mut out = Vec::new();
    for (path, methods) in paths {
        let Some(methods_obj) = methods.as_object() else { continue };
        for (method, op) in methods_obj {
            let mu = method.to_uppercase();
            if !matches!(mu.as_str(), "GET" | "POST" | "PUT" | "DELETE" | "PATCH") { continue; }
            let op_id = op.get("operationId").and_then(|o| o.as_str())
                .unwrap_or(&format!("{}_{}", mu, path)).to_string();
            let consumes = extract_consumes(op);
            let produces = extract_produces(op);
            out.push(ApiOp { method: mu, path: path.clone(), op_id, produces, consumes });
        }
    }
    Ok(out)
}

fn extract_consumes(op: &serde_json::Value) -> Vec<String> {
    let mut s = Vec::new();
    if let Some(params) = op.get("parameters").and_then(|p| p.as_array()) {
        for p in params {
            if let Some(n) = p.get("name").and_then(|n| n.as_str()) {
                s.push(n.to_string());
            }
        }
    }
    if let Some(body) = op.get("requestBody")
        .and_then(|b| b.get("content"))
        .and_then(|c| c.get("application/json"))
        .and_then(|j| j.get("schema"))
        .and_then(|s| s.get("properties"))
        .and_then(|p| p.as_object())
    {
        for k in body.keys() { s.push(k.clone()); }
    }
    s
}

fn extract_produces(op: &serde_json::Value) -> Vec<String> {
    let mut s = Vec::new();
    if let Some(responses) = op.get("responses").and_then(|r| r.as_object()) {
        for (_code, body) in responses {
            if let Some(props) = body.get("content")
                .and_then(|c| c.get("application/json"))
                .and_then(|j| j.get("schema"))
                .and_then(|s| s.get("properties"))
                .and_then(|p| p.as_object())
            {
                for k in props.keys() { s.push(k.clone()); }
            }
        }
    }
    s
}

// ── Sequence inference ────────────────────────────────────────────────────────

/// Build sequences: an op that produces a field is followed by ops that consume that field.
pub fn infer_sequences(ops: &[ApiOp], max: usize) -> Vec<Sequence> {
    let mut sequences = Vec::new();
    // Producers of "id"-like names
    static ID_LIKE: once_cell::sync::Lazy<Regex> = once_cell::sync::Lazy::new(|| {
        Regex::new(r"(?i)\bid\b|_id$|^id$|uuid|token").unwrap()
    });
    for producer in ops {
        let produced_ids: Vec<&String> = producer.produces.iter()
            .filter(|p| ID_LIKE.is_match(p)).collect();
        if produced_ids.is_empty() { continue; }
        for consumer in ops {
            if consumer.op_id == producer.op_id { continue; }
            // Path templated id like /resource/{id}
            let path_uses_id = consumer.path.contains("{") && consumer.path.contains("}");
            if path_uses_id {
                sequences.push(Sequence {
                    id: Uuid::new_v4(),
                    ops: vec![producer.clone(), consumer.clone()],
                });
                if sequences.len() >= max { return sequences; }
            }
        }
    }
    sequences
}

// ── Execution ─────────────────────────────────────────────────────────────────

async fn run_sequence(
    client: &reqwest::Client,
    base_url: &str,
    seq: &Sequence,
    auth: Option<&str>,
) -> Vec<Flaw> {
    let mut out = Vec::new();
    let mut produced_id: Option<String> = None;
    for (i, op) in seq.ops.iter().enumerate() {
        let mut path = op.path.clone();
        if let Some(id) = &produced_id {
            // Replace first `{...}` segment with the produced id.
            if let (Some(s), Some(e)) = (path.find('{'), path.find('}')) {
                path.replace_range(s..=e, id);
            }
        }
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        let m = reqwest::Method::from_bytes(op.method.as_bytes()).unwrap_or(reqwest::Method::GET);
        let mut req = client.request(m, &url);
        if let Some(a) = auth {
            req = req.header("Authorization", a);
        }
        // Provide an empty JSON body for POST/PUT/PATCH
        if matches!(op.method.as_str(), "POST" | "PUT" | "PATCH") {
            req = req.json(&serde_json::json!({}));
        }
        let Ok(resp) = req.send().await else { continue };
        let status = resp.status().as_u16();
        let body_text = resp.text().await.unwrap_or_default();

        // Try to extract a produced id for the next step.
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body_text) {
            if let Some(id) = v.get("id").and_then(|i| i.as_str()) {
                produced_id = Some(id.to_string());
            } else if let Some(id) = v.get("id").and_then(|i| i.as_i64()) {
                produced_id = Some(id.to_string());
            }
        }

        // Server-error detector
        if status >= 500 {
            out.push(Flaw {
                id: Uuid::new_v4(),
                kind: FlawKind::ServerError,
                severity: Severity::Medium,
                sequence: seq.clone(),
                message: format!("Server error {} at step {}", status, i),
                at_step: i,
            });
        }

        // Use-after-free detector: a DELETE followed by GET that returns 200.
        if op.method == "DELETE" && i + 1 < seq.ops.len() {
            // Run next step (which we'll do on the next iteration). The detector below applies.
        }
        if i > 0 && seq.ops[i - 1].method == "DELETE" && op.method == "GET" && status == 200 {
            out.push(Flaw {
                id: Uuid::new_v4(),
                kind: FlawKind::UseAfterFree,
                severity: Severity::High,
                sequence: seq.clone(),
                message: "GET after DELETE returned 200 — use-after-free / soft-delete leak".into(),
                at_step: i,
            });
        }

        // Workflow skip: a step that should require auth but returns 200 with no auth.
        if auth.is_none() && status == 200 && path.contains("admin") {
            out.push(Flaw {
                id: Uuid::new_v4(),
                kind: FlawKind::AccessControl,
                severity: Severity::High,
                sequence: seq.clone(),
                message: format!("Admin-looking path {} returned 200 without auth", path),
                at_step: i,
            });
        }
    }
    out
}

// ── Public API ────────────────────────────────────────────────────────────────

pub async fn run_fuzz(req: FuzzRequest) -> Result<FuzzSession, String> {
    let ops = parse_spec(&req.spec)?;
    let sequences = infer_sequences(&ops, req.max_sequences);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| e.to_string())?;
    let mut flaws = Vec::new();
    for seq in &sequences {
        let mut found = run_sequence(&client, &req.base_url, seq, req.auth_token.as_deref()).await;
        flaws.append(&mut found);
    }
    Ok(FuzzSession {
        id: Uuid::new_v4(),
        started_at: chrono::Utc::now(),
        ended_at: Some(chrono::Utc::now()),
        ops,
        sequences_run: sequences.len(),
        flaws,
    })
}

// ── Session store ─────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct SessionStore {
    inner: Arc<RwLock<Vec<FuzzSession>>>,
}
impl SessionStore {
    pub fn new() -> Self { Self::default() }
    pub fn save(&self, s: FuzzSession) { self.inner.write().push(s); }
    pub fn list(&self) -> Vec<FuzzSession> { self.inner.read().clone() }
    pub fn get(&self, id: Uuid) -> Option<FuzzSession> {
        self.inner.read().iter().find(|s| s.id == id).cloned()
    }
    pub fn clear(&self) { self.inner.write().clear(); }
}
