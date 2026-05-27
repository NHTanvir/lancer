//! Passive JavaScript secret and endpoint extractor.
//!
//! Runs automatically on every JS response flowing through the proxy.
//! Detects secrets, API endpoints, DOM XSS sinks, and source maps.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Type of JS mining finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingType {
    Secret,
    Endpoint,
    Sink,
    SourceMap,
}

/// Severity of a JS mining finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// A single finding produced by the JS miner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsFinding {
    pub id: Uuid,
    #[serde(rename = "type")]
    pub kind: FindingType,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub snippet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub found_at: chrono::DateTime<chrono::Utc>,
}

/// A JS file tracked by the miner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsFile {
    pub url: String,
    pub size_kb: u64,
    pub findings: usize,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

// ── Secret pattern catalog ────────────────────────────────────────────────────

struct SecretPattern {
    name: &'static str,
    severity: Severity,
    regex: Regex,
    confidence: f64,
}

macro_rules! pat {
    ($n:expr, $sev:expr, $re:expr, $conf:expr) => {
        SecretPattern {
            name: $n,
            severity: $sev,
            regex: Regex::new($re).unwrap(),
            confidence: $conf,
        }
    };
}

static SECRET_PATTERNS: Lazy<Vec<SecretPattern>> = Lazy::new(|| vec![
    pat!("AWS Access Key",        Severity::Critical, r"AKIA[0-9A-Z]{16}", 0.99),
    pat!("AWS Secret Key",        Severity::Critical, r#"(?i)aws.{0,20}secret.{0,20}['"][0-9a-zA-Z/+]{40}['"]"#, 0.90),
    pat!("GitHub Token",          Severity::Critical, r"ghp_[a-zA-Z0-9]{36}", 0.99),
    pat!("GitHub OAuth",          Severity::Critical, r"gho_[a-zA-Z0-9]{36}", 0.99),
    pat!("Stripe Live Key",       Severity::Critical, r"sk_live_[0-9a-zA-Z]{24,}", 0.99),
    pat!("Stripe Public Key",     Severity::Low,      r"pk_live_[0-9a-zA-Z]{24,}", 0.95),
    pat!("Slack Bot Token",       Severity::High,     r"xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}", 0.99),
    pat!("Slack User Token",      Severity::High,     r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{12}-[0-9a-f]{32}", 0.99),
    pat!("Google API Key",        Severity::High,     r"AIza[0-9A-Za-z\-_]{35}", 0.97),
    pat!("Firebase URL",          Severity::Medium,   r"[a-z0-9-]+\.firebaseio\.com", 0.80),
    pat!("JWT Token",             Severity::High,     r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", 0.95),
    pat!("RSA Private Key",       Severity::Critical, r"-----BEGIN RSA PRIVATE KEY-----", 0.99),
    pat!("Private Key",           Severity::Critical, r"-----BEGIN PRIVATE KEY-----", 0.99),
    pat!("SendGrid API Key",      Severity::High,     r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", 0.99),
    pat!("Twilio Account SID",    Severity::Medium,   r"AC[a-f0-9]{32}", 0.80),
    pat!("Generic API Key",       Severity::Medium,   r#"(?i)(api[_\-]?key|apikey|api_secret)\s*[=:]\s*["'][a-zA-Z0-9_\-]{16,}["']"#, 0.75),
    pat!("Generic Bearer Token",  Severity::Medium,   r#"Authorization:\s*Bearer\s+[a-zA-Z0-9_\-\.]{20,}"#, 0.85),
    pat!("Basic Auth",            Severity::High,     r#"Authorization:\s*Basic\s+[a-zA-Z0-9+/]{8,}={0,2}"#, 0.90),
    pat!("MongoDB URI",           Severity::High,     r#"mongodb(\+srv)?://[^"'\s]+"#, 0.95),
    pat!("PostgreSQL URI",        Severity::High,     r#"postgres(ql)?://[^"'\s]+"#, 0.95),
    pat!("MySQL URI",             Severity::High,     r#"mysql://[^"'\s]+"#, 0.95),
]);

// ── Endpoint extraction patterns ─────────────────────────────────────────────

static ENDPOINT_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"fetch\s*\(\s*["'](/[^"']+)["']"#).unwrap(),
        Regex::new(r#"axios\.\w+\s*\(\s*["'](/[^"']+)["']"#).unwrap(),
        Regex::new(r#"\$\.(?:get|post|ajax|put|delete)\s*\(\s*["'](/[^"']+)["']"#).unwrap(),
        Regex::new(r#"XMLHttpRequest[^;]+open\s*\([^,]+,\s*["']([^"']+)["']"#).unwrap(),
        Regex::new(r#"url\s*:\s*["'](/api/[^"']+)["']"#).unwrap(),
        Regex::new(r#"path\s*:\s*["'](/v\d+/[^"']+)["']"#).unwrap(),
    ]
});

// ── DOM sink patterns ─────────────────────────────────────────────────────────

static SINK_PATTERNS: &[(&str, &str)] = &[
    ("innerHTML",      r"\.innerHTML\s*=\s*\w"),
    ("outerHTML",      r"\.outerHTML\s*=\s*\w"),
    ("document.write", r"document\.write\s*\("),
    ("eval",           r"\beval\s*\("),
    ("Function()",     r"\bnew\s+Function\s*\("),
    ("setTimeout-str", r#"setTimeout\s*\(\s*["']"#),
    ("setInterval-str",r#"setInterval\s*\(\s*["']"#),
    ("location.href",  r"location\.href\s*="),
    ("location.replace",r"location\.replace\s*\("),
    ("insertAdjacentHTML",r"insertAdjacentHTML\s*\("),
];

// ── Shannon entropy ───────────────────────────────────────────────────────────

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for b in s.bytes() { counts[b as usize] += 1; }
    let len = s.len() as f64;
    counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / len; -p * p.log2() })
        .sum()
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Analyse a JS source string and return all findings.
pub fn analyse(url: &str, source: &str) -> Vec<JsFinding> {
    let mut findings = Vec::new();
    let now = chrono::Utc::now();

    // Detect source map reference
    if source.contains("sourceMappingURL=") {
        findings.push(JsFinding {
            id: Uuid::new_v4(),
            kind: FindingType::SourceMap,
            severity: Severity::Info,
            file: url.to_string(),
            line: source.lines().position(|l| l.contains("sourceMappingURL=")).unwrap_or(0) + 1,
            snippet: "Source map reference detected — decoded sources may contain sensitive code".to_string(),
            secret_type: None,
            confidence: Some(1.0),
            endpoint: None,
            method: None,
            sink: None,
            source: None,
            found_at: now,
        });
    }

    // Scan for secrets
    for pat in SECRET_PATTERNS.iter() {
        for mat in pat.regex.find_iter(source) {
            let line = source[..mat.start()].lines().count() + 1;
            let snippet = mat.as_str().to_string();
            findings.push(JsFinding {
                id: Uuid::new_v4(),
                kind: FindingType::Secret,
                severity: pat.severity.clone(),
                file: url.to_string(),
                line,
                snippet,
                secret_type: Some(pat.name.to_string()),
                confidence: Some(pat.confidence),
                endpoint: None,
                method: None,
                sink: None,
                source: None,
                found_at: now,
            });
        }
    }

    // Entropy-based secret detection on base64-like strings
    let entropy_re = Regex::new(r#"["']([a-zA-Z0-9+/=]{32,})["']"#).unwrap();
    for mat in entropy_re.captures_iter(source) {
        let s = mat.get(1).map(|m| m.as_str()).unwrap_or("");
        if shannon_entropy(s) >= 4.0 {
            let start = mat.get(0).map(|m| m.start()).unwrap_or(0);
            let line = source[..start].lines().count() + 1;
            findings.push(JsFinding {
                id: Uuid::new_v4(),
                kind: FindingType::Secret,
                severity: Severity::Medium,
                file: url.to_string(),
                line,
                snippet: format!("High-entropy string (entropy={:.2}): {}…", shannon_entropy(s), &s[..s.len().min(40)]),
                secret_type: Some("High-entropy string".to_string()),
                confidence: Some(0.6),
                endpoint: None,
                method: None,
                sink: None,
                source: None,
                found_at: now,
            });
        }
    }

    // Endpoint extraction
    for re in ENDPOINT_PATTERNS.iter() {
        for cap in re.captures_iter(source) {
            let ep = cap.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            if ep.is_empty() { continue; }
            let start = cap.get(0).map(|m| m.start()).unwrap_or(0);
            let line = source[..start].lines().count() + 1;
            let snippet_str = cap.get(0).map(|m| m.as_str()).unwrap_or("").to_string();
            let method = if snippet_str.to_lowercase().contains("post") { "POST" } else { "GET" }.to_string();
            findings.push(JsFinding {
                id: Uuid::new_v4(),
                kind: FindingType::Endpoint,
                severity: Severity::Info,
                file: url.to_string(),
                line,
                snippet: snippet_str,
                secret_type: None,
                confidence: Some(0.85),
                endpoint: Some(ep),
                method: Some(method),
                sink: None,
                source: None,
                found_at: now,
            });
        }
    }

    // DOM sink detection
    for (sink_name, pattern) in SINK_PATTERNS {
        let re = Regex::new(pattern).unwrap();
        for mat in re.find_iter(source) {
            let line = source[..mat.start()].lines().count() + 1;
            let severity = match *sink_name {
                "eval" | "Function()" | "innerHTML" | "outerHTML" | "document.write" => Severity::High,
                _ => Severity::Medium,
            };
            findings.push(JsFinding {
                id: Uuid::new_v4(),
                kind: FindingType::Sink,
                severity,
                file: url.to_string(),
                line,
                snippet: mat.as_str().to_string(),
                secret_type: None,
                confidence: Some(0.80),
                endpoint: None,
                method: None,
                sink: Some(sink_name.to_string()),
                source: Some("unknown — trace required".to_string()),
                found_at: now,
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_key() {
        let src = r#"const KEY = "AKIAIOSFODNN7EXAMPLE";"#;
        let findings = analyse("https://example.com/app.js", src);
        assert!(findings.iter().any(|f| f.kind == FindingType::Secret));
    }

    #[test]
    fn detects_fetch_endpoint() {
        let src = r#"fetch("/api/v1/users", {method: "GET"})"#;
        let findings = analyse("https://example.com/app.js", src);
        assert!(findings.iter().any(|f| f.kind == FindingType::Endpoint));
    }

    #[test]
    fn detects_innerhtml_sink() {
        let src = r#"el.innerHTML = userData"#;
        let findings = analyse("https://example.com/app.js", src);
        assert!(findings.iter().any(|f| f.kind == FindingType::Sink));
    }

    #[test]
    fn entropy_detects_high_entropy_string() {
        let high_entropy = "aB3kX9mP2nQr7sT4uV8wY1zA5bC6dE0";
        assert!(shannon_entropy(high_entropy) >= 4.0);
    }
}
