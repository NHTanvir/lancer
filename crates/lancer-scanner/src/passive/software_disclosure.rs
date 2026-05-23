//! Software/version disclosure via Server / X-Powered-By / etc.

use async_trait::async_trait;
use lancer_core::{HttpRequest, HttpResponse};
use lancer_storage::issues::{Confidence, Issue, Severity};

use crate::PassiveCheck;

pub struct SoftwareDisclosureCheck;

#[async_trait]
impl PassiveCheck for SoftwareDisclosureCheck {
    fn id(&self) -> &'static str {
        "passive.software_disclosure"
    }
    fn name(&self) -> &'static str {
        "Server / framework version disclosed"
    }
    async fn check(&self, request: &HttpRequest, response: &HttpResponse) -> Vec<Issue> {
        let mut issues = Vec::new();
        for h in &["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"] {
            if let Some(v) = response.header(h) {
                if v.chars().any(|c| c.is_ascii_digit()) {
                    issues.push(super::issue(
                        self.name(),
                        Severity::Info,
                        Confidence::Firm,
                        request,
                        format!("`{h}` header contains version: `{v}`"),
                        Some("Remove or generalize software-version headers."),
                    ));
                }
            }
        }
        issues
    }
}
