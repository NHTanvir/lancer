//! XPath injection.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;
use regex::Regex;

use crate::insertion::{substitute, InsertionPoint};
use crate::ActiveCheck;

pub struct XPathCheck;

const PROBES: &[&str] = &[
    "' or '1'='1",
    "x' or name()='username' or 'x'='y",
    "//*[1=1]",
    "x' or 1=1 or 'x'='y",
];

#[async_trait]
impl ActiveCheck for XPathCheck {
    fn id(&self) -> &'static str {
        "active.xpath"
    }
    fn name(&self) -> &'static str {
        "XPath injection"
    }
    async fn run(
        &self,
        client: &HttpClient,
        base: &HttpRequest,
        point: &InsertionPoint,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        let err_rx = Regex::new(
            r"(?i)System\.Xml\.XPath|MS\.Internal\.Xml|XPathException|Sablotron|saxon|invalid xpath|Unable to compile",
        )
        .unwrap();
        for p in PROBES {
            let Some(req) = substitute(base, point, p) else { continue };
            let Ok(resp) = client.send(&req).await else { continue };
            let body = resp.body_text().unwrap_or("");
            if err_rx.is_match(body) {
                let mut i = Issue::new(
                    base.meta.host.clone(),
                    base.url(),
                    "XPath injection",
                    Severity::High,
                    Confidence::Firm,
                    format!("payload `{p}` produced an XPath error message"),
                );
                i.remediation = Some(
                    "Parametrize XPath queries; never concatenate user input directly into expressions.".into(),
                );
                i.notes = Some(format!("insertion point: {} ({:?})", point.name, point.location));
                i.check_id = Some(self.id().into());
                issues.push(i);
                return issues;
            }
        }
        issues
    }
}
