//! JavaScript-comment-embedded secrets and TODO leaks.

use async_trait::async_trait;
use lancer_core::{HttpRequest, HttpResponse};
use lancer_storage::issues::{Confidence, Issue, Severity};
use regex::Regex;

use crate::PassiveCheck;

pub struct JsSecretCheck;

#[async_trait]
impl PassiveCheck for JsSecretCheck {
    fn id(&self) -> &'static str {
        "passive.js_secrets"
    }
    fn name(&self) -> &'static str {
        "Secret-looking value in JavaScript source"
    }
    async fn check(&self, request: &HttpRequest, response: &HttpResponse) -> Vec<Issue> {
        let ct = response.header("Content-Type").unwrap_or("");
        if !ct.contains("javascript") && !ct.contains("text/html") {
            return Vec::new();
        }
        let body = match response.body_text() {
            Some(b) => b,
            None => return Vec::new(),
        };
        let mut issues = Vec::new();
        let assignment = Regex::new(
            r#"(?i)\b(api[_-]?key|secret|password|token|auth)\b\s*[:=]\s*['"]([^'"]{6,200})['"]"#,
        )
        .unwrap();
        for cap in assignment.captures_iter(body) {
            let name = &cap[1];
            let val = &cap[2];
            if looks_placeholder(val) {
                continue;
            }
            issues.push(super::issue(
                "Hard-coded credential in JavaScript",
                Severity::Medium,
                Confidence::Tentative,
                request,
                format!("`{name}` literal looks like a real secret"),
                Some("Move secrets out of client-side code; fetch them via authenticated APIs."),
            ));
        }
        issues
    }
}

fn looks_placeholder(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    [
        "xxx", "your_", "placeholder", "example", "todo", "changeme", "secret_here", "<", "{",
    ]
    .iter()
    .any(|t| lower.contains(t))
}
