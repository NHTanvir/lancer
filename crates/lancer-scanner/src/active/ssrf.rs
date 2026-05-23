//! SSRF (in-band) detection.
//!
//! For true blind SSRF we need a Collaborator host (see
//! `lancer_scanner::collaborator`). This check only fires when an in-band
//! indicator surfaces — e.g., an AWS metadata response leaks through the proxy.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;
use regex::Regex;

use crate::insertion::{substitute, InsertionPoint};
use crate::ActiveCheck;

pub struct SsrfCheck;

const PROBES: &[&str] = &[
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:22",
    "file:///etc/hostname",
];

#[async_trait]
impl ActiveCheck for SsrfCheck {
    fn id(&self) -> &'static str {
        "active.ssrf"
    }
    fn name(&self) -> &'static str {
        "Server-side request forgery (in-band indicator)"
    }
    async fn run(
        &self,
        client: &HttpClient,
        base: &HttpRequest,
        point: &InsertionPoint,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        let aws_rx = Regex::new(r"(?i)ami-id|instance-id|iam/security-credentials").unwrap();
        let gcp_rx = Regex::new(r"(?i)Metadata-Flavor: Google|computeMetadata/v1/").unwrap();
        for p in PROBES {
            let Some(req) = substitute(base, point, p) else { continue };
            let Ok(resp) = client.send(&req).await else { continue };
            let body = resp.body_text().unwrap_or("");
            if aws_rx.is_match(body) {
                issues.push(make(base, point, "AWS instance metadata", Confidence::Firm));
                break;
            } else if gcp_rx.is_match(body) {
                issues.push(make(base, point, "GCP instance metadata", Confidence::Firm));
                break;
            } else if (200..300).contains(&resp.status) && body.contains("SSH-") {
                issues.push(make(base, point, "SSH banner from 127.0.0.1", Confidence::Firm));
                break;
            }
        }
        issues
    }
}

fn make(base: &HttpRequest, point: &InsertionPoint, evidence: &str, conf: Confidence) -> Issue {
    let mut i = Issue::new(
        base.meta.host.clone(),
        base.url(),
        "Server-side request forgery",
        Severity::High,
        conf,
        format!("response contains: {evidence}"),
    );
    i.remediation = Some(
        "Validate user-supplied URLs against an allow-list; block link-local and loopback ranges."
            .into(),
    );
    i.notes = Some(format!("insertion point: {} ({:?})", point.name, point.location));
    i.check_id = Some("active.ssrf".into());
    i
}
