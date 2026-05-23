//! Mixed-content (http://… loaded from a https:// page).

use async_trait::async_trait;
use lancer_core::{HttpRequest, HttpResponse};
use lancer_storage::issues::{Confidence, Issue, Severity};
use regex::Regex;

use crate::PassiveCheck;

pub struct MixedContentCheck;

#[async_trait]
impl PassiveCheck for MixedContentCheck {
    fn id(&self) -> &'static str {
        "passive.mixed_content"
    }
    fn name(&self) -> &'static str {
        "Mixed content"
    }
    async fn check(&self, request: &HttpRequest, response: &HttpResponse) -> Vec<Issue> {
        if request.meta.scheme != "https" {
            return Vec::new();
        }
        let body = match response.body_text() {
            Some(b) => b,
            None => return Vec::new(),
        };
        let rx = Regex::new(r#"(src|href)\s*=\s*["']http://[^"']+"#).unwrap();
        let mut issues = Vec::new();
        for m in rx.find_iter(body).take(5) {
            issues.push(super::issue(
                self.name(),
                Severity::Low,
                Confidence::Firm,
                request,
                format!("HTTPS page references plaintext resource: `{}`", &body[m.start()..m.end()]),
                Some("Use protocol-relative or https:// URLs for all subresources."),
            ));
        }
        issues
    }
}
