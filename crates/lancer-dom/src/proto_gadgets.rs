//! Prototype-pollution gadget scanner — known library-side gadget shapes.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GadgetHit {
    pub gadget: String,
    pub library: Option<String>,
    pub line: usize,
    pub snippet: String,
}

static PATTERNS: Lazy<Vec<(&'static str, Option<&'static str>, Regex)>> = Lazy::new(|| {
    vec![
        ("jQuery $.extend(true, …)", Some("jQuery"), Regex::new(r"\$\.extend\s*\(\s*true\s*,").unwrap()),
        ("lodash _.merge / mergeWith", Some("lodash"), Regex::new(r"_\.(merge|mergeWith|defaultsDeep)\s*\(").unwrap()),
        ("Object.assign with user input", None, Regex::new(r"Object\.assign\s*\(\s*\w+\s*,\s*JSON\.parse").unwrap()),
        ("eval() of merged config", None, Regex::new(r"eval\s*\(\s*\w+\.script").unwrap()),
        ("script.src = config.url", None, Regex::new(r"\.src\s*=\s*\w+\.url").unwrap()),
        ("innerHTML = config.html", None, Regex::new(r"\.innerHTML\s*=\s*\w+\.html").unwrap()),
        ("AngularJS $on", Some("AngularJS"), Regex::new(r#"\$rootScope\.\$on\s*\(\s*['"]\$"#).unwrap()),
    ]
});

pub fn find_gadgets(body: &str) -> Vec<GadgetHit> {
    let mut out = Vec::new();
    for (line_idx, line) in body.lines().enumerate() {
        for (name, lib, rx) in PATTERNS.iter() {
            if rx.is_match(line) {
                out.push(GadgetHit {
                    gadget: name.to_string(),
                    library: lib.map(|s| s.to_string()),
                    line: line_idx + 1,
                    snippet: line.trim().to_string(),
                });
            }
        }
    }
    out
}
