//! §44 MCP Server Scanner — MCP-scan equivalent.
//!
//! Scans Model Context Protocol servers for tool-poisoning, prompt-injection,
//! rug-pull, cross-server tool collision, and insecure-tool issues.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Transport { Stdio, Sse, WebSocket, Http }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub transport: Transport,
    /// For stdio: `./binary --flag`. For others: a URL.
    pub server: String,
    #[serde(default = "default_depth")]
    pub depth: ScanDepth,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanDepth { Quick, Full }

fn default_depth() -> ScanDepth { ScanDepth::Full }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity { Info, Low, Medium, High, Critical }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input_schema: Option<serde_json::Value>,
    pub description_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResource {
    pub uri: String,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub category: String,
    pub severity: Severity,
    pub tool: Option<String>,
    pub message: String,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: Uuid,
    pub server: String,
    pub tools: Vec<McpTool>,
    pub resources: Vec<McpResource>,
    pub findings: Vec<Finding>,
    pub scanned_at: chrono::DateTime<chrono::Utc>,
}

// ── Suspicious-pattern catalog ────────────────────────────────────────────────

static HIDDEN_INSTRUCTION_RE: Lazy<Regex> = Lazy::new(|| Regex::new(
    r"(?i)(?:ignore|forget|override).{0,40}(?:previous|prior|above|system).{0,40}(?:instruction|prompt|directive)"
).unwrap());

static UNICODE_TAGS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(
    r"[\u{E0000}-\u{E007F}]"
).unwrap());

static HOMOGLYPH_RE: Lazy<Regex> = Lazy::new(|| Regex::new(
    r"[\u{0430}\u{043E}\u{0435}\u{0440}\u{0441}\u{1FAD9}]"  // Cyrillic а/о/е/р/с
).unwrap());

static PROMPT_INJECT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(
    r"(?i)(?:</?system>|</?instruction>|</?prompt>|\bdo anything\b|\bjailbreak\b)"
).unwrap());

static PERMISSIVE_PARAM_RE: Lazy<Regex> = Lazy::new(|| Regex::new(
    r#"(?i)"(?:command|path|url|arg|shell|cmd|exec|raw|script)"\s*:"#
).unwrap());

// ── Analysis ──────────────────────────────────────────────────────────────────

fn hash_description(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())[..16].to_string()
}

fn analyze_tool(tool: &McpTool, all_tools: &[McpTool]) -> Vec<Finding> {
    let mut out = Vec::new();
    let desc = &tool.description;

    if HIDDEN_INSTRUCTION_RE.is_match(desc) {
        out.push(Finding {
            id: Uuid::new_v4(),
            category: "hidden-instruction".into(),
            severity: Severity::Critical,
            tool: Some(tool.name.clone()),
            message: format!("Tool `{}` description contains hidden instruction-override pattern", tool.name),
            evidence: Some(desc.chars().take(200).collect()),
        });
    }
    if UNICODE_TAGS_RE.is_match(desc) {
        out.push(Finding {
            id: Uuid::new_v4(),
            category: "unicode-tag".into(),
            severity: Severity::High,
            tool: Some(tool.name.clone()),
            message: format!("Tool `{}` description contains Unicode tag characters (steganography)", tool.name),
            evidence: None,
        });
    }
    if HOMOGLYPH_RE.is_match(desc) {
        out.push(Finding {
            id: Uuid::new_v4(),
            category: "homoglyph".into(),
            severity: Severity::Medium,
            tool: Some(tool.name.clone()),
            message: format!("Tool `{}` description contains homoglyph characters", tool.name),
            evidence: None,
        });
    }
    if PROMPT_INJECT_RE.is_match(desc) {
        out.push(Finding {
            id: Uuid::new_v4(),
            category: "prompt-injection".into(),
            severity: Severity::High,
            tool: Some(tool.name.clone()),
            message: format!("Tool `{}` description contains prompt-injection markup", tool.name),
            evidence: Some(desc.chars().take(200).collect()),
        });
    }
    if let Some(schema) = &tool.input_schema {
        let schema_str = serde_json::to_string(schema).unwrap_or_default();
        if PERMISSIVE_PARAM_RE.is_match(&schema_str) {
            out.push(Finding {
                id: Uuid::new_v4(),
                category: "permissive-param".into(),
                severity: Severity::Medium,
                tool: Some(tool.name.clone()),
                message: format!("Tool `{}` accepts overly permissive parameter (command/path/url/shell)", tool.name),
                evidence: Some(schema_str.chars().take(300).collect()),
            });
        }
    }
    // Name collision across the same server
    let count = all_tools.iter().filter(|t| t.name == tool.name).count();
    if count > 1 {
        out.push(Finding {
            id: Uuid::new_v4(),
            category: "name-collision".into(),
            severity: Severity::Medium,
            tool: Some(tool.name.clone()),
            message: format!("Tool name `{}` appears {count} times", tool.name),
            evidence: None,
        });
    }
    out
}

// ── JSON-RPC transport ────────────────────────────────────────────────────────

async fn http_rpc(server: &str, method: &str, params: serde_json::Value) -> Option<serde_json::Value> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .build()
        .ok()?;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let resp = client.post(server).json(&body).send().await.ok()?;
    let v: serde_json::Value = resp.json().await.ok()?;
    v.get("result").cloned()
}

async fn stdio_rpc(_cmd: &str, _method: &str, _params: serde_json::Value) -> Option<serde_json::Value> {
    // Real implementation: spawn child process, write JSON-RPC to stdin, read stdout line.
    // Omitted in this simplified port — the GUI flow normally uses HTTP/SSE.
    None
}

async fn enumerate_tools(req: &ScanRequest) -> Vec<McpTool> {
    let raw = match req.transport {
        Transport::Http | Transport::Sse => http_rpc(&req.server, "tools/list", serde_json::json!({})).await,
        Transport::Stdio                  => stdio_rpc(&req.server, "tools/list", serde_json::json!({})).await,
        Transport::WebSocket              => None, // WS not implemented here
    };
    let Some(raw) = raw else { return Vec::new() };
    let Some(tools) = raw.get("tools").and_then(|t| t.as_array()) else { return Vec::new() };
    tools.iter().filter_map(|t| {
        let name = t.get("name")?.as_str()?.to_string();
        let description = t.get("description").and_then(|d| d.as_str()).unwrap_or("").to_string();
        let input_schema = t.get("inputSchema").cloned();
        let description_hash = hash_description(&description);
        Some(McpTool { name, description, input_schema, description_hash })
    }).collect()
}

async fn enumerate_resources(req: &ScanRequest) -> Vec<McpResource> {
    let raw = match req.transport {
        Transport::Http | Transport::Sse => http_rpc(&req.server, "resources/list", serde_json::json!({})).await,
        _ => None,
    };
    let Some(raw) = raw else { return Vec::new() };
    let Some(items) = raw.get("resources").and_then(|r| r.as_array()) else { return Vec::new() };
    items.iter().filter_map(|r| {
        let uri = r.get("uri")?.as_str()?.to_string();
        let name = r.get("name").and_then(|n| n.as_str()).map(|s| s.to_string());
        let description = r.get("description").and_then(|d| d.as_str()).map(|s| s.to_string());
        Some(McpResource { uri, name, description })
    }).collect()
}

// ── Public API ────────────────────────────────────────────────────────────────

pub async fn scan(req: ScanRequest) -> ScanResult {
    let tools = enumerate_tools(&req).await;
    let resources = enumerate_resources(&req).await;
    let mut findings = Vec::new();
    for tool in &tools {
        findings.extend(analyze_tool(tool, &tools));
    }
    // Resource analysis: path-traversal-prone URIs.
    for r in &resources {
        if r.uri.contains("..") || r.uri.starts_with("file:///") {
            findings.push(Finding {
                id: Uuid::new_v4(),
                category: "resource-traversal".into(),
                severity: Severity::High,
                tool: None,
                message: format!("Resource URI looks like arbitrary file access: {}", r.uri),
                evidence: None,
            });
        }
    }
    ScanResult {
        id: Uuid::new_v4(),
        server: req.server.clone(),
        tools,
        resources,
        findings,
        scanned_at: chrono::Utc::now(),
    }
}

/// Compare two scans of the same server — detect rug-pull (silent description changes).
pub fn diff_rug_pull(prev: &ScanResult, current: &ScanResult) -> Vec<Finding> {
    let mut out = Vec::new();
    for prev_tool in &prev.tools {
        let Some(cur_tool) = current.tools.iter().find(|t| t.name == prev_tool.name) else { continue };
        if prev_tool.description_hash != cur_tool.description_hash {
            out.push(Finding {
                id: Uuid::new_v4(),
                category: "rug-pull".into(),
                severity: Severity::Critical,
                tool: Some(cur_tool.name.clone()),
                message: format!("Tool `{}` description changed since last scan (rug-pull)", cur_tool.name),
                evidence: Some(format!("prev hash {} → current hash {}", prev_tool.description_hash, cur_tool.description_hash)),
            });
        }
    }
    out
}

/// Detect cross-server tool collision (shadowing attack).
pub fn cross_server_collision(scans: &[ScanResult]) -> Vec<Finding> {
    use std::collections::HashMap;
    let mut by_name: HashMap<String, Vec<(&str, &str)>> = HashMap::new();
    for s in scans {
        for t in &s.tools {
            by_name.entry(t.name.clone()).or_default().push((s.server.as_str(), t.description_hash.as_str()));
        }
    }
    let mut out = Vec::new();
    for (name, owners) in by_name {
        if owners.len() > 1 {
            // Same name, different desc-hash = potential shadowing.
            let mut hashes: Vec<&str> = owners.iter().map(|(_, h)| *h).collect();
            hashes.sort(); hashes.dedup();
            if hashes.len() > 1 {
                out.push(Finding {
                    id: Uuid::new_v4(),
                    category: "cross-server-collision".into(),
                    severity: Severity::High,
                    tool: Some(name.clone()),
                    message: format!("Tool `{}` exists on {} servers with different definitions (potential shadowing)", name, owners.len()),
                    evidence: Some(owners.iter().map(|(s, _)| *s).collect::<Vec<_>>().join(", ")),
                });
            }
        }
    }
    out
}
