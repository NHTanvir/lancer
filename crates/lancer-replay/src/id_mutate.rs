//! ID-mutation fuzzer.
//!
//! Detects ID-like values (sequential integers, UUIDs) in a captured request,
//! generates neighbouring/edge mutations, replays each, and flags any mutation
//! that reaches a *different* valid object (the classic IDOR signal).

use anyhow::Result;
use lancer_core::HttpRequest;
use lancer_tools::HttpClient;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdCandidate {
    pub location: String, // "url" | "body"
    pub value: String,
    pub kind: String, // "int" | "uuid"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdHit {
    pub location: String,
    pub original: String,
    pub mutated: String,
    pub status: u16,
    pub length: usize,
    /// Similarity of this response's body to the baseline (same-id) response.
    pub similarity_to_baseline: f64,
    /// True when this looks like a successfully-reached *other* object.
    pub interesting: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdFuzzReport {
    pub baseline_status: u16,
    pub baseline_length: usize,
    pub candidates: Vec<IdCandidate>,
    pub hits: Vec<IdHit>,
}

fn detect(url: &str, body: &str) -> Vec<IdCandidate> {
    let uuid_re = Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}").unwrap();
    let int_re = Regex::new(r"\b\d{1,12}\b").unwrap();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (loc, text) in [("url", url), ("body", body)] {
        let mut uuid_ranges: Vec<std::ops::Range<usize>> = Vec::new();
        for m in uuid_re.find_iter(text) {
            uuid_ranges.push(m.range());
            let v = m.as_str().to_string();
            if seen.insert(format!("{loc}:{v}")) {
                out.push(IdCandidate { location: loc.into(), value: v, kind: "uuid".into() });
            }
        }
        for m in int_re.find_iter(text) {
            // Skip integer runs that fall inside an already-detected UUID.
            if uuid_ranges.iter().any(|r| m.start() < r.end && r.start < m.end()) {
                continue;
            }
            let v = m.as_str().to_string();
            if seen.insert(format!("{loc}:{v}")) {
                out.push(IdCandidate { location: loc.into(), value: v, kind: "int".into() });
            }
        }
    }
    out
}

fn mutations(c: &IdCandidate) -> Vec<String> {
    match c.kind.as_str() {
        "int" => {
            let n: i64 = c.value.parse().unwrap_or(0);
            let mut v: Vec<i64> = vec![n - 1, n + 1, n - 10, n + 10, 0, 1, n + 1000, 99999];
            v.retain(|&x| x >= 0 && x.to_string() != c.value);
            v.sort_unstable();
            v.dedup();
            v.into_iter().map(|x| x.to_string()).collect()
        }
        _ => {
            // UUID: zero, max, and a single-hex-digit flip.
            let mut out = vec![
                "00000000-0000-0000-0000-000000000000".to_string(),
                "ffffffff-ffff-ffff-ffff-ffffffffffff".to_string(),
            ];
            if let Some(first) = c.value.chars().next() {
                let flipped = if first == '0' { '1' } else { '0' };
                out.push(format!("{flipped}{}", &c.value[1..]));
            }
            out.retain(|m| m != &c.value);
            out
        }
    }
}

/// Build a request with `original` replaced by `mutated` in the chosen location.
fn mutate_request(base: &HttpRequest, c: &IdCandidate, mutated: &str) -> HttpRequest {
    if c.location == "url" {
        // Mutate only the path/query, never the whole reconstructed URL, so the
        // scheme/host/port (carried in req.meta) can never be rewritten.
        let mut req = base.clone();
        req.path = base.path.replacen(&c.value, mutated, 1);
        req
    } else {
        let mut req = base.clone();
        // Byte-level first-occurrence splice that preserves all original bytes
        // (ID candidates are ASCII, so this is lossless for non-UTF-8 bodies).
        let needle = c.value.as_bytes();
        if let Some(pos) = base.body.windows(needle.len()).position(|w| w == needle) {
            let mut new_body = Vec::with_capacity(base.body.len() + mutated.len());
            new_body.extend_from_slice(&base.body[..pos]);
            new_body.extend_from_slice(mutated.as_bytes());
            new_body.extend_from_slice(&base.body[pos + needle.len()..]);
            req.body = bytes::Bytes::from(new_body);
        }
        // else: candidate not found at byte level (shouldn't happen since it was
        // detected from the body); leave body unchanged.
        req
    }
}

pub async fn fuzz_ids(client: &HttpClient, base: &HttpRequest) -> Result<IdFuzzReport> {
    // Baseline (unmodified) response.
    let baseline = client.send(base).await.ok();
    let (baseline_status, baseline_body, baseline_length) = match &baseline {
        Some(r) => (r.status, r.body_text().unwrap_or("").to_string(), r.body.len()),
        None => (0, String::new(), 0),
    };

    let url = base.url();
    let body = String::from_utf8_lossy(&base.body).to_string();
    let candidates = detect(&url, &body);

    let mut hits = Vec::new();
    // Cap total replays so a request full of numbers can't explode.
    let mut budget = 120usize;
    for c in &candidates {
        for mutated in mutations(c) {
            if budget == 0 { break; }
            budget -= 1;
            let req = mutate_request(base, c, &mutated);
            let Ok(resp) = client.send(&req).await else { continue };
            let rbody = resp.body_text().unwrap_or("");
            let sim = crate::token_similarity(&baseline_body, rbody);
            // Interesting: 200 OK, content meaningfully different from baseline,
            // but not an empty/error page (length within an order of magnitude).
            let interesting = resp.status == 200
                && sim < 0.95
                && resp.body.len() > 0
                && (baseline_length == 0 || (resp.body.len() as f64) > (baseline_length as f64) * 0.3);
            hits.push(IdHit {
                location: c.location.clone(),
                original: c.value.clone(),
                mutated,
                status: resp.status,
                length: resp.body.len(),
                similarity_to_baseline: (sim * 1000.0).round() / 1000.0,
                interesting,
            });
        }
    }
    Ok(IdFuzzReport { baseline_status, baseline_length, candidates, hits })
}
