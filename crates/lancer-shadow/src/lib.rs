//! §47 AI Repeater Variants — Shadow Repeater equivalent.
//!
//! When the user clicks Send in Repeater, this module generates 3-5 mutation
//! variants (param value tweaks, header additions, encoding changes, case
//! flips, path traversal additions) and runs them in the background through
//! the proxy. If a variant's response substantially differs from the
//! baseline, surface as a "shadow hit".

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MutationFamily {
    AuthBypass,
    Idor,
    Injection,
    Encoding,
    ParameterPollution,
    PathTraversal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowRequest {
    pub raw_request: String,
    pub families: Vec<MutationFamily>,
    #[serde(default = "default_max_variants")]
    pub max_variants: usize,
}

fn default_max_variants() -> usize { 5 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowVariant {
    pub id: Uuid,
    pub family: MutationFamily,
    pub description: String,
    pub raw_request: String,
    pub status: Option<u16>,
    pub length: Option<usize>,
    pub score: f64, // 0.0 (boring) – 1.0 (very different)
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ── Mutation engine (offline — no LLM required, but augmentable) ──────────────

pub fn generate_variants(req: &ShadowRequest) -> Vec<ShadowVariant> {
    let mut out = Vec::new();
    for family in &req.families {
        let mutations: Vec<(String, String)> = match family {
            MutationFamily::AuthBypass => vec![
                ("X-Original-URL header".into(), header_mutation(&req.raw_request, "X-Original-URL", "/admin")),
                ("Lowercased Authorization".into(), case_flip_header(&req.raw_request, "Authorization")),
            ],
            MutationFamily::Idor => vec![
                ("Bump first numeric id".into(), bump_first_numeric(&req.raw_request, 1)),
                ("Decrement first numeric id".into(), bump_first_numeric(&req.raw_request, -1)),
            ],
            MutationFamily::Injection => vec![
                ("Inject single quote".into(), inject_into_first_param(&req.raw_request, "'")),
                ("Inject {{7*7}}".into(), inject_into_first_param(&req.raw_request, "{{7*7}}")),
                ("Inject ${jndi:ldap://}".into(), inject_into_first_param(&req.raw_request, "${jndi:ldap://test}")),
            ],
            MutationFamily::Encoding => vec![
                ("URL-encode body".into(), url_encode_body(&req.raw_request)),
                ("Double URL-encode".into(), double_url_encode_body(&req.raw_request)),
            ],
            MutationFamily::ParameterPollution => vec![
                ("Duplicate param".into(), duplicate_first_param(&req.raw_request)),
            ],
            MutationFamily::PathTraversal => vec![
                ("Append ../..".into(), append_path(&req.raw_request, "/../..")),
                ("Append /.;/".into(), append_path(&req.raw_request, "/.;/")),
            ],
        };
        for (desc, raw) in mutations {
            out.push(ShadowVariant {
                id: Uuid::new_v4(),
                family: *family,
                description: desc,
                raw_request: raw,
                status: None,
                length: None,
                score: 0.0,
                created_at: chrono::Utc::now(),
            });
        }
        if out.len() >= req.max_variants { break; }
    }
    out.truncate(req.max_variants);
    out
}

// ── Mutation helpers ──────────────────────────────────────────────────────────

fn header_mutation(raw: &str, name: &str, value: &str) -> String {
    // Insert before the blank line separating headers from body.
    if let Some(idx) = raw.find("\r\n\r\n").or_else(|| raw.find("\n\n")) {
        let mut new = String::new();
        new.push_str(&raw[..idx]);
        new.push_str(&format!("\r\n{name}: {value}"));
        new.push_str(&raw[idx..]);
        return new;
    }
    format!("{raw}{name}: {value}\r\n")
}

fn case_flip_header(raw: &str, name: &str) -> String {
    raw.lines().map(|l| {
        if l.to_lowercase().starts_with(&format!("{}:", name.to_lowercase())) {
            l.to_lowercase()
        } else {
            l.to_string()
        }
    }).collect::<Vec<_>>().join("\n")
}

fn bump_first_numeric(raw: &str, delta: i64) -> String {
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut end = i;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            let num: i64 = raw[start..end].parse().unwrap_or(0);
            let new = (num + delta).max(0);
            return format!("{}{}{}", &raw[..start], new, &raw[end..]);
        }
        i += 1;
    }
    raw.to_string()
}

fn inject_into_first_param(raw: &str, payload: &str) -> String {
    if let Some(qpos) = raw.find('?') {
        if let Some(eq_pos) = raw[qpos..].find('=') {
            let inj_at = qpos + eq_pos + 1;
            let end_at = raw[inj_at..]
                .find(|c: char| c == '&' || c == ' ' || c == '\r' || c == '\n')
                .map(|p| inj_at + p)
                .unwrap_or(inj_at);
            return format!("{}{}{}", &raw[..inj_at], payload, &raw[end_at..]);
        }
    }
    raw.to_string()
}

fn url_encode_body(raw: &str) -> String {
    if let Some(idx) = raw.find("\r\n\r\n").or_else(|| raw.find("\n\n")) {
        let (head, body) = raw.split_at(idx);
        let body_text = body.trim_start_matches("\r\n").trim_start_matches("\n");
        let encoded: String = body_text.bytes().map(|b| {
            if b.is_ascii_alphanumeric() { (b as char).to_string() }
            else { format!("%{:02X}", b) }
        }).collect();
        return format!("{head}\r\n\r\n{encoded}");
    }
    raw.to_string()
}

fn double_url_encode_body(raw: &str) -> String {
    let once = url_encode_body(raw);
    url_encode_body(&once)
}

fn duplicate_first_param(raw: &str) -> String {
    if let Some(qpos) = raw.find('?') {
        if let Some(eq_pos) = raw[qpos..].find('=') {
            let key_start = qpos + 1;
            let key_end = qpos + eq_pos;
            let key = &raw[key_start..key_end];
            return raw.replacen(&format!("{key}="), &format!("{key}=&{key}="), 1);
        }
    }
    raw.to_string()
}

fn append_path(raw: &str, suffix: &str) -> String {
    if let Some(first_space) = raw.find(' ') {
        // METHOD path HTTP/1.1
        let after_method = &raw[first_space + 1..];
        if let Some(next_space) = after_method.find(' ') {
            let path_end = first_space + 1 + next_space;
            return format!("{}{}{}", &raw[..path_end], suffix, &raw[path_end..]);
        }
    }
    raw.to_string()
}

// ── Scoring ───────────────────────────────────────────────────────────────────

pub fn score_against_baseline(baseline_status: u16, baseline_length: usize, status: u16, length: usize) -> f64 {
    let mut s = 0.0;
    if status != baseline_status { s += 0.5; }
    let len_diff = (length as i64 - baseline_length as i64).abs() as f64;
    s += (len_diff / (baseline_length.max(1) as f64)).min(0.5);
    s.min(1.0)
}

// ── Cache (per baseline-hash) ────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct ShadowCache {
    inner: Arc<RwLock<HashMap<String, Vec<ShadowVariant>>>>,
}

impl ShadowCache {
    pub fn new() -> Self { Self::default() }

    pub fn hash(req: &str) -> String {
        let mut h = Sha256::new();
        h.update(req.as_bytes());
        hex::encode(h.finalize())[..16].to_string()
    }

    pub fn get(&self, hash: &str) -> Option<Vec<ShadowVariant>> {
        self.inner.read().get(hash).cloned()
    }
    pub fn put(&self, hash: String, v: Vec<ShadowVariant>) {
        self.inner.write().insert(hash, v);
    }
}
