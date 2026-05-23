//! NoSQL injection (MongoDB-style operator injection + JS-eval injection).

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;
use regex::Regex;

use crate::insertion::{substitute, InsertionPoint};
use crate::ActiveCheck;

pub struct NoSqliCheck;

const PROBES: &[&str] = &[
    "{\"$gt\":\"\"}",
    "{\"$ne\":null}",
    "[$ne]=1",
    "';return true;//",
    "');return true;//",
    "'||'1'=='1",
];

#[async_trait]
impl ActiveCheck for NoSqliCheck {
    fn id(&self) -> &'static str {
        "active.nosqli"
    }
    fn name(&self) -> &'static str {
        "NoSQL injection"
    }
    async fn run(
        &self,
        client: &HttpClient,
        base: &HttpRequest,
        point: &InsertionPoint,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        let err_rx = Regex::new(r"(?i)mongo|bson|\$where|cast_error|syntax_error_on_eval").unwrap();
        let Ok(baseline) = client.send(base).await else { return issues };
        let baseline_len = baseline.body.len() as i64;
        for p in PROBES {
            let Some(req) = substitute(base, point, p) else { continue };
            let Ok(resp) = client.send(&req).await else { continue };
            let body = resp.body_text().unwrap_or("");
            let delta = (resp.body.len() as i64 - baseline_len).abs();
            if err_rx.is_match(body) {
                issues.push(make("NoSQL error message", base, point, Confidence::Firm));
                break;
            }
            if delta > 200 && (200..300).contains(&resp.status) {
                issues.push(make(
                    "NoSQL operator injection (length delta)",
                    base,
                    point,
                    Confidence::Tentative,
                ));
                break;
            }
        }
        issues
    }
}

fn make(reason: &str, base: &HttpRequest, point: &InsertionPoint, conf: Confidence) -> Issue {
    let mut i = Issue::new(
        base.meta.host.clone(),
        base.url(),
        "NoSQL injection",
        Severity::High,
        conf,
        reason.to_string(),
    );
    i.remediation = Some(
        "Validate input types; never pass unsanitised JSON straight to NoSQL drivers.".into(),
    );
    i.notes = Some(format!("insertion point: {} ({:?})", point.name, point.location));
    i.check_id = Some("active.nosqli".into());
    i
}
