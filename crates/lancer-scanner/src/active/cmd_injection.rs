//! OS command injection (synchronous + time-blind).

use std::time::Instant;

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;
use regex::Regex;

use crate::insertion::{substitute, InsertionPoint};
use crate::ActiveCheck;

pub struct CommandInjectionCheck;

const ECHO_TOKEN: &str = "L4NCER_CMDi_TOKEN_88c2";

const PROBES: &[&str] = &[
    "; echo L4NCER_CMDi_TOKEN_88c2",
    "| echo L4NCER_CMDi_TOKEN_88c2",
    "`echo L4NCER_CMDi_TOKEN_88c2`",
    "$(echo L4NCER_CMDi_TOKEN_88c2)",
    "& echo L4NCER_CMDi_TOKEN_88c2",
    "%0aecho L4NCER_CMDi_TOKEN_88c2",
];

const TIME_PROBES: &[&str] = &["; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)", "%0asleep 5"];

#[async_trait]
impl ActiveCheck for CommandInjectionCheck {
    fn id(&self) -> &'static str {
        "active.cmd_injection"
    }
    fn name(&self) -> &'static str {
        "OS command injection"
    }
    async fn run(
        &self,
        client: &HttpClient,
        base: &HttpRequest,
        point: &InsertionPoint,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        let token_rx = Regex::new(ECHO_TOKEN).unwrap();

        for p in PROBES {
            let Some(req) = substitute(base, point, p) else { continue };
            let Ok(resp) = client.send(&req).await else { continue };
            if let Some(body) = resp.body_text() {
                if token_rx.is_match(body) {
                    issues.push(make("token reflected", base, point, Confidence::Firm));
                    return issues;
                }
            }
        }

        for p in TIME_PROBES.iter().take(1) {
            let Some(req) = substitute(base, point, p) else { continue };
            let started = Instant::now();
            let Ok(_resp) = client.send(&req).await else { continue };
            let elapsed = started.elapsed().as_secs_f64();
            if elapsed > 4.5 {
                issues.push(make(
                    &format!("sleep payload caused {elapsed:.1}s delay"),
                    base,
                    point,
                    Confidence::Firm,
                ));
                return issues;
            }
        }
        issues
    }
}

fn make(reason: &str, base: &HttpRequest, point: &InsertionPoint, conf: Confidence) -> Issue {
    let mut i = Issue::new(
        base.meta.host.clone(),
        base.url(),
        "OS command injection",
        Severity::Critical,
        conf,
        reason.to_string(),
    );
    i.remediation = Some(
        "Never pass user input to shell APIs; use argument arrays + a well-vetted execution helper."
            .into(),
    );
    i.notes = Some(format!("insertion point: {} ({:?})", point.name, point.location));
    i.check_id = Some("active.cmd_injection".into());
    i
}
