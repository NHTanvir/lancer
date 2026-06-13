//! Response differ — structured, response-aware comparison of two raw HTTP
//! responses (status line / headers / body), with a similarity score and
//! per-line added/removed accounting.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespDiff {
    pub status_a: String,
    pub status_b: String,
    pub same_status: bool,
    pub len_a: usize,
    pub len_b: usize,
    /// 0.0–1.0 body token similarity.
    pub similarity: f64,
    pub added_lines: usize,
    pub removed_lines: usize,
    /// Headers present in A but not B (name → value).
    pub headers_only_a: Vec<(String, String)>,
    /// Headers present in B but not A.
    pub headers_only_b: Vec<(String, String)>,
    /// Headers whose value changed (name, value_a, value_b).
    pub headers_changed: Vec<(String, String, String)>,
}

struct Parsed {
    status: String,
    headers: Vec<(String, String)>,
    body: String,
}

fn parse(raw: &str) -> Parsed {
    let norm = raw.replace("\r\n", "\n");
    let mut lines = norm.split('\n');
    let status = lines.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    let mut body_start = None;
    let mut rest = String::new();
    let mut in_body = false;
    for line in lines {
        if in_body {
            rest.push_str(line);
            rest.push('\n');
            continue;
        }
        if line.is_empty() {
            in_body = true;
            body_start = Some(true);
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let _ = body_start;
    Parsed { status, headers, body: rest.trim_end().to_string() }
}

pub fn diff_responses(a_raw: &str, b_raw: &str) -> RespDiff {
    let a = parse(a_raw);
    let b = parse(b_raw);

    let lines_a: std::collections::HashSet<&str> = a.body.lines().collect();
    let lines_b: std::collections::HashSet<&str> = b.body.lines().collect();
    let added = lines_b.difference(&lines_a).count();
    let removed = lines_a.difference(&lines_b).count();

    let map_a: std::collections::HashMap<String, String> =
        a.headers.iter().map(|(k, v)| (k.to_lowercase(), v.clone())).collect();
    let map_b: std::collections::HashMap<String, String> =
        b.headers.iter().map(|(k, v)| (k.to_lowercase(), v.clone())).collect();

    let mut only_a = Vec::new();
    let mut changed = Vec::new();
    for (k, v) in &a.headers {
        match map_b.get(&k.to_lowercase()) {
            None => only_a.push((k.clone(), v.clone())),
            Some(vb) if vb != v => changed.push((k.clone(), v.clone(), vb.clone())),
            _ => {}
        }
    }
    let only_b: Vec<(String, String)> = b
        .headers
        .iter()
        .filter(|(k, _)| !map_a.contains_key(&k.to_lowercase()))
        .cloned()
        .collect();

    RespDiff {
        same_status: a.status == b.status,
        status_a: a.status,
        status_b: b.status,
        len_a: a.body.len(),
        len_b: b.body.len(),
        similarity: (crate::token_similarity(&a.body, &b.body) * 1000.0).round() / 1000.0,
        added_lines: added,
        removed_lines: removed,
        headers_only_a: only_a,
        headers_only_b: only_b,
        headers_changed: changed,
    }
}
