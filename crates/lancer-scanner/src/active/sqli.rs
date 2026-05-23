//! SQL-injection check: error-based + boolean-blind + time-blind.

use std::time::Instant;

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;
use regex::Regex;

use crate::insertion::{substitute, InsertionPoint};
use crate::ActiveCheck;

pub struct SqliCheck;

const ERROR_PAYLOADS: &[&str] = &["'", "\"", "')", "' OR '1'='1", "' AND 1=convert(int,@@version)--"];
const BOOLEAN_TRUE: &str = "' OR '1'='1";
const BOOLEAN_FALSE: &str = "' AND '1'='2";
const TIME_PAYLOADS: &[&str] = &[
    "' OR SLEEP(5)-- -",
    "1) OR pg_sleep(5)-- -",
    "' OR WAITFOR DELAY '0:0:5'-- -",
];

#[async_trait]
impl ActiveCheck for SqliCheck {
    fn id(&self) -> &'static str {
        "active.sqli"
    }
    fn name(&self) -> &'static str {
        "SQL injection"
    }

    async fn run(
        &self,
        client: &HttpClient,
        base: &HttpRequest,
        point: &InsertionPoint,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        let error_rx = Regex::new(r"(?i)you have an error in your sql syntax|warning: mysql|unclosed quotation mark|sqlstate\[|pg_query|ora-\d{5}|odbc sql server driver").unwrap();

        // Error-based
        for p in ERROR_PAYLOADS {
            let Some(req) = substitute(base, point, p) else { continue };
            let Ok(resp) = client.send(&req).await else { continue };
            if let Some(body) = resp.body_text() {
                if error_rx.is_match(body) {
                    issues.push(make_issue(
                        base, point, "error-based",
                        format!("payload `{p}` produced a database error message"),
                        Severity::High, Confidence::Firm,
                    ));
                    break;
                }
            }
        }

        // Boolean-blind
        if let (Some(req_t), Some(req_f)) =
            (substitute(base, point, BOOLEAN_TRUE), substitute(base, point, BOOLEAN_FALSE))
        {
            if let (Ok(rt), Ok(rf)) = (client.send(&req_t).await, client.send(&req_f).await) {
                let len_t = rt.body.len() as i64;
                let len_f = rf.body.len() as i64;
                if (len_t - len_f).abs() > 200 && (rt.status == rf.status) {
                    issues.push(make_issue(
                        base, point, "boolean-blind",
                        format!("boolean payloads produced significant length delta ({len_t} vs {len_f})"),
                        Severity::High, Confidence::Tentative,
                    ));
                }
            }
        }

        // Time-blind (limit to one payload to bound runtime).
        for p in TIME_PAYLOADS.iter().take(1) {
            let Some(req) = substitute(base, point, p) else { continue };
            let started = Instant::now();
            let Ok(_resp) = client.send(&req).await else { continue };
            let elapsed = started.elapsed().as_secs_f64();
            if elapsed > 4.5 {
                issues.push(make_issue(
                    base, point, "time-blind",
                    format!("payload `{p}` produced a {elapsed:.1}s delay"),
                    Severity::High, Confidence::Firm,
                ));
                break;
            }
        }

        issues
    }
}

fn make_issue(
    base: &HttpRequest,
    point: &InsertionPoint,
    variant: &str,
    desc: String,
    sev: Severity,
    conf: Confidence,
) -> Issue {
    let mut i = Issue::new(
        base.meta.host.clone(),
        base.url(),
        format!("SQL injection ({variant})"),
        sev,
        conf,
        desc,
    );
    i.remediation = Some(
        "Use parameterized queries / prepared statements; never concatenate user input into SQL."
            .to_string(),
    );
    i.notes = Some(format!("Insertion point: {} ({:?})", point.name, point.location));
    i.check_id = Some("active.sqli".to_string());
    i
}
