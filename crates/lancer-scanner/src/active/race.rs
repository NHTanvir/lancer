//! Race-condition (single-packet attack) helper.
//!
//! Fires N copies of the same request in parallel and reports if any unusual
//! response distribution appears (e.g., one 200 + many 409s where the docs say
//! the action is supposed to be idempotent).

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

pub struct RaceConditionCheck;

const PARALLEL: usize = 12;

#[async_trait]
impl ActiveCheck for RaceConditionCheck {
    fn id(&self) -> &'static str { "active.race_condition" }
    fn name(&self) -> &'static str { "Race condition candidate" }
    async fn run(&self, client: &HttpClient, base: &HttpRequest, point: &InsertionPoint) -> Vec<Issue> {
        // Point-agnostic check: run a single time per request, not once per insertion point.
        if let Some(first) = crate::insertion::find_insertion_points(base).first() {
            if first.name != point.name || first.location != point.location {
                return Vec::new();
            }
        }
        // Only fire on state-changing verbs.
        if !matches!(base.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
            return Vec::new();
        }
        let mut handles = Vec::with_capacity(PARALLEL);
        for _ in 0..PARALLEL {
            let client = client.clone();
            let req = base.clone();
            handles.push(tokio::spawn(async move { client.send(&req).await.ok().map(|r| r.status) }));
        }
        let mut statuses: Vec<u16> = Vec::with_capacity(PARALLEL);
        for h in handles {
            if let Ok(Some(s)) = h.await {
                statuses.push(s);
            }
        }
        if statuses.is_empty() { return Vec::new(); }
        let success: usize = statuses.iter().filter(|&&s| (200..300).contains(&s)).count();
        if success > 1 && success < statuses.len() {
            let mut i = Issue::new(base.meta.host.clone(), base.url(), self.name(),
                Severity::Medium, Confidence::Tentative,
                format!("of {} concurrent requests, {} succeeded — endpoint may be racy", statuses.len(), success));
            i.remediation = Some("Use database-level uniqueness constraints or row-level locks; idempotency keys for client-driven operations.".into());
            i.check_id = Some(self.id().into());
            return vec![i];
        }
        Vec::new()
    }
}
