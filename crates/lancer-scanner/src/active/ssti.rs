//! Server-Side Template Injection — Jinja/Twig/ERB/Freemarker/Velocity.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;

use crate::insertion::{substitute, InsertionPoint};
use crate::ActiveCheck;

pub struct SstiCheck;

/// Each probe is `(payload, expected_substring_in_response)`.
const PROBES: &[(&str, &str)] = &[
    ("{{7*7}}", "49"),                                // Jinja2 / Twig / Liquid
    ("${7*7}", "49"),                                 // Freemarker / Velocity
    ("<%= 7*7 %>", "49"),                             // ERB / EJS
    ("#{7*7}", "49"),                                 // Ruby slim / Smarty
    ("{{ 'lancer'|upper }}", "LANCER"),               // Jinja2 filter
    ("{% if 1==1 %}lancer_yes{% endif %}", "lancer_yes"),
];

#[async_trait]
impl ActiveCheck for SstiCheck {
    fn id(&self) -> &'static str {
        "active.ssti"
    }
    fn name(&self) -> &'static str {
        "Server-side template injection"
    }
    async fn run(
        &self,
        client: &HttpClient,
        base: &HttpRequest,
        point: &InsertionPoint,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        let Ok(baseline) = client.send(base).await else { return issues };
        let baseline_body = baseline.body_text().unwrap_or("").to_string();
        for (payload, expected) in PROBES {
            if baseline_body.contains(expected) {
                continue; // skip ambiguous probes if expected already appears
            }
            let Some(req) = substitute(base, point, payload) else { continue };
            let Ok(resp) = client.send(&req).await else { continue };
            let body = resp.body_text().unwrap_or("");
            if body.contains(expected) {
                let mut i = Issue::new(
                    base.meta.host.clone(),
                    base.url(),
                    "Server-side template injection",
                    Severity::High,
                    Confidence::Firm,
                    format!("payload `{payload}` produced expected expression result `{expected}`"),
                );
                i.remediation = Some(
                    "Don't render user input as a template; use safe-by-default templating with autoescape.".into(),
                );
                i.notes = Some(format!("insertion point: {} ({:?})", point.name, point.location));
                i.check_id = Some("active.ssti".into());
                issues.push(i);
                return issues;
            }
        }
        issues
    }
}
