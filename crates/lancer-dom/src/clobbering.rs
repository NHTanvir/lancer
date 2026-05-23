//! DOM clobbering detection — looks for HTML that exposes named globals
//! (form / iframe / anchor / object with name/id matching common globals).

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClobberHit {
    pub line: usize,
    pub element: String,
    pub clobbers: String,
    pub snippet: String,
}

const RISKY_NAMES: &[&str] = &[
    "config", "options", "app", "globals", "settings", "params", "data",
    "init", "constructor", "prototype", "toString", "valueOf", "documentURI",
    "domain", "URL",
];

static TAG_RX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"<(form|iframe|a|object|input|img)[^>]*\s+(?:id|name)\s*=\s*["']([^"']+)["']"#).unwrap());

pub fn detect_clobbering(html: &str) -> Vec<ClobberHit> {
    let mut out = Vec::new();
    for (line_idx, line) in html.lines().enumerate() {
        for cap in TAG_RX.captures_iter(line) {
            let tag = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let nameval = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            if RISKY_NAMES.iter().any(|n| n.eq_ignore_ascii_case(nameval)) {
                out.push(ClobberHit {
                    line: line_idx + 1,
                    element: tag.to_string(),
                    clobbers: nameval.to_string(),
                    snippet: line.trim().to_string(),
                });
            }
        }
    }
    out
}
