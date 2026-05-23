//! Mass-assignment / over-binding.
//!
//! Re-sends the request with a few "interesting" JSON keys added and looks for
//! evidence in the response that the extra fields were accepted.

use async_trait::async_trait;
use bytes::Bytes;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;
use regex::Regex;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

pub struct MassAssignmentCheck;

const CANARY: &str = "L4NCER_MASS_88c2";

const KEYS: &[&str] = &[
    "isAdmin", "is_admin", "admin", "role", "permissions", "groups", "verified", "balance",
    "userId", "id",
];

#[async_trait]
impl ActiveCheck for MassAssignmentCheck {
    fn id(&self) -> &'static str {
        "active.mass_assignment"
    }
    fn name(&self) -> &'static str {
        "Mass assignment"
    }
    async fn run(
        &self,
        client: &HttpClient,
        base: &HttpRequest,
        point: &InsertionPoint,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        // Only act on JSON-bodied requests, and run once per request.
        let ct = base.header("Content-Type").unwrap_or("");
        if !ct.contains("json") {
            return issues;
        }
        if !matches!(
            point.location,
            lancer_core::ParamLocation::JsonValue | lancer_core::ParamLocation::JsonKey
        ) {
            return issues;
        }
        if point.name != base
            .body_text()
            .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
            .and_then(|v| {
                v.as_object()
                    .and_then(|m| m.keys().next().cloned())
            })
            .unwrap_or_default()
        {
            // run only against the first JSON key we observe to dedupe
            return issues;
        }
        let mut v: serde_json::Value =
            serde_json::from_str(base.body_text().unwrap_or("{}")).unwrap_or_default();
        if let serde_json::Value::Object(map) = &mut v {
            for k in KEYS {
                map.entry((*k).into())
                    .or_insert(serde_json::Value::String(CANARY.into()));
            }
        }
        let mut req = base.clone();
        req.body = Bytes::from(serde_json::to_vec(&v).unwrap_or_default());
        let Ok(resp) = client.send(&req).await else { return issues };
        if !(200..400).contains(&resp.status) {
            return issues;
        }
        let body = resp.body_text().unwrap_or("");
        let rx = Regex::new(&format!(r#""(?:{})"\s*:\s*"?{}"#, KEYS.join("|"), CANARY)).unwrap();
        if rx.is_match(body) {
            let mut i = Issue::new(
                base.meta.host.clone(),
                base.url(),
                self.name(),
                Severity::High,
                Confidence::Firm,
                "server accepted and reflected a privileged-looking extra field".into(),
            );
            i.remediation = Some(
                "Bind only allow-listed fields; never deserialize directly into domain models.".into(),
            );
            i.check_id = Some(self.id().into());
            issues.push(i);
        }
        issues
    }
}
