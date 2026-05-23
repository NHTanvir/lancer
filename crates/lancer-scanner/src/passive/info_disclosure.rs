//! Information disclosure — stack traces, internal IPs, paths, debug pages, etc.

use async_trait::async_trait;
use lancer_core::{HttpRequest, HttpResponse};
use lancer_storage::issues::{Confidence, Issue, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

use crate::PassiveCheck;

pub struct InfoDisclosureCheck;

static PATTERNS: Lazy<Vec<(&'static str, Regex, Severity)>> = Lazy::new(|| {
    vec![
        (
            "Java stack trace",
            Regex::new(r"(?m)^\s*at\s+[\w.$]+\([\w./:]+\.java:\d+\)").unwrap(),
            Severity::Low,
        ),
        (
            "Python traceback",
            Regex::new(r"(?m)^\s*File \".+\", line \d+,").unwrap(),
            Severity::Low,
        ),
        (
            ".NET stack trace",
            Regex::new(r"at [\w.]+\.\w+\([^)]*\)\s+in\s+[A-Za-z]:\\").unwrap(),
            Severity::Low,
        ),
        (
            "PHP error",
            Regex::new(r"(?i)<b>(Warning|Fatal error|Notice|Parse error)</b>:").unwrap(),
            Severity::Medium,
        ),
        (
            "Internal IPv4 address",
            Regex::new(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b").unwrap(),
            Severity::Info,
        ),
        (
            "Source-map reference",
            Regex::new(r"//[#@] sourceMappingURL=").unwrap(),
            Severity::Info,
        ),
        (
            "AWS access key",
            Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
            Severity::High,
        ),
        (
            "GitHub PAT",
            Regex::new(r"\bghp_[A-Za-z0-9]{36}\b").unwrap(),
            Severity::High,
        ),
        (
            "Slack token",
            Regex::new(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b").unwrap(),
            Severity::High,
        ),
        (
            "Private key",
            Regex::new(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE) PRIVATE KEY-----").unwrap(),
            Severity::High,
        ),
        (
            "Credit card-like number",
            Regex::new(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b").unwrap(),
            Severity::Medium,
        ),
    ]
});

#[async_trait]
impl PassiveCheck for InfoDisclosureCheck {
    fn id(&self) -> &'static str {
        "passive.info_disclosure"
    }
    fn name(&self) -> &'static str {
        "Information disclosure"
    }
    async fn check(&self, request: &HttpRequest, response: &HttpResponse) -> Vec<Issue> {
        let body = match response.body_text() {
            Some(b) => b,
            None => return Vec::new(),
        };
        let mut issues = Vec::new();
        for (name, rx, sev) in PATTERNS.iter() {
            if let Some(m) = rx.find(body) {
                let snippet = body[m.start()..(m.end().min(m.start() + 120))].to_string();
                issues.push(super::issue(
                    name,
                    *sev,
                    Confidence::Tentative,
                    request,
                    format!("response contains sensitive pattern: `{snippet}`"),
                    Some("Remove the sensitive content from the response, or restrict it to authorized users."),
                ));
            }
        }
        issues
    }
}
