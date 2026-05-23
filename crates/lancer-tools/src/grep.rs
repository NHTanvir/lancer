//! Result-table analysis: grep-match, grep-extract, grep-payloads.

use lancer_core::HttpResponse;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepConfig {
    /// Strings that, when present in the response, set a boolean flag column.
    pub match_strings: Vec<String>,
    /// Regex extracts that yield a column value (first capture group, or whole
    /// match if no group).
    pub extracts: Vec<GrepExtract>,
    /// If true, flag responses that contained the payload literally.
    pub reflect_payload: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepExtract {
    pub label: String,
    pub regex: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrepResult {
    /// Whether each `match_strings` entry was present.
    pub matches: Vec<bool>,
    pub extracts: Vec<Option<String>>,
    pub payload_reflected: bool,
}

pub fn analyze(cfg: &GrepConfig, resp: &HttpResponse, payload: &str) -> GrepResult {
    let body = resp.body_text().unwrap_or("");
    let matches = cfg.match_strings.iter().map(|s| body.contains(s)).collect();
    let extracts = cfg
        .extracts
        .iter()
        .map(|e| {
            Regex::new(&e.regex).ok().and_then(|rx| {
                rx.captures(body).map(|c| {
                    c.get(1)
                        .or_else(|| c.get(0))
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default()
                })
            })
        })
        .collect();
    let payload_reflected = if cfg.reflect_payload && !payload.is_empty() {
        body.contains(payload)
    } else {
        false
    };
    GrepResult { matches, extracts, payload_reflected }
}
