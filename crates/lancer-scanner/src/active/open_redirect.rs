//! Open-redirect detection.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;

use crate::insertion::{substitute, InsertionPoint};
use crate::ActiveCheck;

pub struct OpenRedirectCheck;

const PROBES: &[&str] = &[
    "https://evil.example.com/",
    "//evil.example.com/",
    "/\\evil.example.com",
    "https:%2f%2fevil.example.com/",
];

#[async_trait]
impl ActiveCheck for OpenRedirectCheck {
    fn id(&self) -> &'static str {
        "active.open_redirect"
    }
    fn name(&self) -> &'static str {
        "Open redirect"
    }
    async fn run(
        &self,
        client: &HttpClient,
        base: &HttpRequest,
        point: &InsertionPoint,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        for p in PROBES {
            let Some(req) = substitute(base, point, p) else { continue };
            let Ok(resp) = client.send(&req).await else { continue };
            if !(300..400).contains(&resp.status) {
                continue;
            }
            let loc = resp.header("Location").unwrap_or("");
            if loc.contains("evil.example.com") {
                let mut i = Issue::new(
                    base.meta.host.clone(),
                    base.url(),
                    "Open redirect",
                    Severity::Medium,
                    Confidence::Firm,
                    format!("Location header points to attacker domain after payload `{p}`: `{loc}`"),
                );
                i.remediation = Some(
                    "Validate redirect targets against an allow-list of internal paths or domains."
                        .into(),
                );
                i.notes = Some(format!("insertion point: {} ({:?})", point.name, point.location));
                i.check_id = Some(self.id().to_string());
                issues.push(i);
                break;
            }
        }
        issues
    }
}
