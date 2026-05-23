//! CORS misconfiguration check.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

pub struct CorsCheck;

#[async_trait]
impl ActiveCheck for CorsCheck {
    fn id(&self) -> &'static str {
        "active.cors"
    }
    fn name(&self) -> &'static str {
        "CORS misconfiguration"
    }
    async fn run(
        &self,
        client: &HttpClient,
        base: &HttpRequest,
        _point: &InsertionPoint,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        let evil = "https://evil.example.com";
        let mut req = base.clone();
        req.set_header("Origin", evil);
        let Ok(resp) = client.send(&req).await else { return issues };
        let acao = resp.header("Access-Control-Allow-Origin").unwrap_or("").to_string();
        let acac = resp
            .header("Access-Control-Allow-Credentials")
            .unwrap_or("")
            .to_lowercase();
        let (sev, conf, desc) = if acao == "*" && acac == "true" {
            (
                Severity::High,
                Confidence::Firm,
                "ACAO `*` combined with ACAC `true` (browser may still enforce, but config is invalid)",
            )
        } else if acao == evil {
            (
                Severity::High,
                Confidence::Firm,
                "ACAO reflected attacker-controlled Origin verbatim",
            )
        } else if acao == "null" && acac == "true" {
            (
                Severity::High,
                Confidence::Firm,
                "ACAO `null` permits sandboxed-iframe / file:// attacks",
            )
        } else if acao == "*" {
            (
                Severity::Low,
                Confidence::Firm,
                "ACAO `*` exposes the resource to any origin (no credentials)",
            )
        } else {
            return issues;
        };
        let mut i = Issue::new(
            base.meta.host.clone(),
            base.url(),
            "CORS misconfiguration",
            sev,
            conf,
            desc.to_string(),
        );
        i.remediation = Some(
            "Use an Origin allow-list; do not reflect arbitrary Origin headers; never combine ACAO `*` with credentials.".into(),
        );
        i.check_id = Some(self.id().into());
        issues.push(i);
        issues
    }
}
