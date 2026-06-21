//! Reflected XSS check.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;
use uuid::Uuid;

use crate::insertion::{substitute, InsertionPoint};
use crate::ActiveCheck;

pub struct XssCheck;

const PROBE_TEMPLATES: &[&str] = &[
    "<script>l@n_{tag}</script>",
    "\"><img src=x onerror=l@n_{tag}>",
    "javascript:l@n_{tag}",
    "'><svg/onload=l@n_{tag}>",
];

#[async_trait]
impl ActiveCheck for XssCheck {
    fn id(&self) -> &'static str {
        "active.xss"
    }
    fn name(&self) -> &'static str {
        "Reflected XSS"
    }
    async fn run(
        &self,
        client: &HttpClient,
        base: &HttpRequest,
        point: &InsertionPoint,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        let tag = Uuid::new_v4().simple().to_string();
        let canary = format!("l@n_{tag}");
        for tmpl in PROBE_TEMPLATES {
            let payload = tmpl.replace("{tag}", &tag);
            let Some(req) = substitute(base, point, &payload) else { continue };
            let Ok(resp) = client.send(&req).await else { continue };
            let Some(body) = resp.body_text() else { continue };
            if body.contains(&payload) {
                let mut i = Issue::new(
                    base.meta.host.clone(),
                    base.url(),
                    "Reflected XSS (likely)",
                    Severity::High,
                    Confidence::Firm,
                    format!("payload reflected unsanitised in response: `{payload}`"),
                );
                i.remediation = Some(
                    "Escape user input on output; use CSP; prefer auto-escaping templating engines."
                        .into(),
                );
                i.check_id = Some(self.id().to_string());
                i.notes = Some(format!("insertion point: {} ({:?})", point.name, point.location));
                issues.push(i);
            } else if body.contains(&canary) {
                let mut i = Issue::new(
                    base.meta.host.clone(),
                    base.url(),
                    "Canary reflection (possible filtered XSS)",
                    Severity::Medium,
                    Confidence::Tentative,
                    format!("canary `{canary}` reflected but full payload was not — partial filtering"),
                );
                i.check_id = Some(self.id().to_string());
                i.notes = Some(format!("insertion point: {} ({:?})", point.name, point.location));
                issues.push(i);
            }
        }
        issues
    }
}
