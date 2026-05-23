//! Notes TLS configuration issues that show up in the response without needing
//! a separate handshake (e.g., HSTS-on-HTTP redirect missing, mixed scheme).

use async_trait::async_trait;
use lancer_core::{HttpRequest, HttpResponse};
use lancer_storage::issues::{Confidence, Issue, Severity};

use crate::PassiveCheck;

pub struct TlsConfigurationCheck;

#[async_trait]
impl PassiveCheck for TlsConfigurationCheck {
    fn id(&self) -> &'static str {
        "passive.tls_config"
    }
    fn name(&self) -> &'static str {
        "TLS configuration issue"
    }
    async fn check(&self, request: &HttpRequest, response: &HttpResponse) -> Vec<Issue> {
        let mut issues = Vec::new();
        // HSTS only meaningful on HTTPS, already covered by header check.
        // Flag plaintext form-action on HTTPS pages.
        if request.meta.scheme == "https" {
            if let Some(body) = response.body_text() {
                if body.contains("action=\"http://") || body.contains("action='http://") {
                    issues.push(super::issue(
                        self.name(),
                        Severity::Medium,
                        Confidence::Firm,
                        request,
                        "form submits to a plaintext http:// URL".to_string(),
                        Some("Submit forms to https:// to prevent credential interception."),
                    ));
                }
            }
        }
        issues
    }
}
