//! Path-traversal / LFI check.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;

use crate::insertion::{substitute, InsertionPoint};
use crate::ActiveCheck;

pub struct TraversalCheck;

const PROBES: &[&str] = &[
    "../../../etc/passwd",
    "....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
];

const UNIX_INDICATORS: &[&str] = &["root:x:0:0:", "daemon:", "/bin/bash"];
const WIN_INDICATORS: &[&str] = &["[fonts]", "[extensions]", "[mci extensions]"];

#[async_trait]
impl ActiveCheck for TraversalCheck {
    fn id(&self) -> &'static str {
        "active.traversal"
    }
    fn name(&self) -> &'static str {
        "Path traversal / Local file inclusion"
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
            let Some(body) = resp.body_text() else { continue };
            if UNIX_INDICATORS.iter().any(|m| body.contains(m)) {
                issues.push(make(base, point, "Unix /etc/passwd contents", "Linux"));
                break;
            }
            if WIN_INDICATORS.iter().any(|m| body.contains(m)) {
                issues.push(make(base, point, "Windows win.ini contents", "Windows"));
                break;
            }
        }
        issues
    }
}

fn make(base: &HttpRequest, point: &InsertionPoint, desc: &str, os: &str) -> Issue {
    let mut i = Issue::new(
        base.meta.host.clone(),
        base.url(),
        "Path traversal",
        Severity::High,
        Confidence::Firm,
        format!("traversal payload returned {desc} ({os})"),
    );
    i.remediation = Some("Normalize and validate paths; never pass user input to filesystem APIs.".into());
    i.notes = Some(format!("insertion point: {} ({:?})", point.name, point.location));
    i.check_id = Some("active.traversal".into());
    i
}
