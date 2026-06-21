//! HTTP Host-header injection.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

pub struct HostHeaderCheck;

const PROBES: &[&str] = &[
    "evil.example.com",
    "evil.example.com:443",
];

#[async_trait]
impl ActiveCheck for HostHeaderCheck {
    fn id(&self) -> &'static str {
        "active.host_header"
    }
    fn name(&self) -> &'static str {
        "HTTP Host-header injection"
    }
    async fn run(
        &self,
        client: &HttpClient,
        base: &HttpRequest,
        _point: &InsertionPoint,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        // Only run once per request — this check doesn't depend on the insertion
        // point. Throttle by only running for the first insertion point.
        if !is_first_point(_point) {
            return issues;
        }
        for evil in PROBES {
            let mut req = base.clone();
            req.set_header("Host", *evil);
            let Ok(resp) = client.send(&req).await else { continue };
            let location = resp.header("Location").unwrap_or("");
            let body = resp.body_text().unwrap_or("");
            if location.contains(evil) || body.contains(evil) {
                let mut i = Issue::new(
                    base.meta.host.clone(),
                    base.url(),
                    "Host-header injection",
                    Severity::Medium,
                    Confidence::Firm,
                    format!("evil Host `{evil}` reflected into response"),
                );
                i.remediation = Some(
                    "Validate the Host header against an allow-list, or use absolute URLs from a trusted base.".into(),
                );
                i.check_id = Some(self.id().into());
                issues.push(i);
                return issues;
            }
        }
        issues
    }
}

fn is_first_point(point: &InsertionPoint) -> bool {
    // The Host header is offered as exactly one insertion point per HTTP/1.1
    // request, so use it as the stable single-run sentinel for this
    // request-level check (it does not depend on the insertion point).
    point.name.eq_ignore_ascii_case("Host")
}
