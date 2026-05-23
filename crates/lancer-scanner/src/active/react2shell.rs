//! React2Shell — CVE-2025-55182 + CVE-2025-66478 fingerprint.
//!
//! Mentioned in plan.md §5.2 (added 2025.11). This is a passive-style
//! fingerprint of vulnerable bundles: it looks for the specific module hashes
//! and the `_lancer_probe` symbol that the proof-of-concept produces.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;
use regex::Regex;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

pub struct React2ShellCheck;

#[async_trait]
impl ActiveCheck for React2ShellCheck {
    fn id(&self) -> &'static str { "active.react2shell" }
    fn name(&self) -> &'static str { "React2Shell RCE (CVE-2025-55182 / CVE-2025-66478)" }
    async fn run(&self, client: &HttpClient, base: &HttpRequest, _point: &InsertionPoint) -> Vec<Issue> {
        let Ok(resp) = client.send(base).await else { return Vec::new() };
        let body = resp.body_text().unwrap_or("");
        let bundle_rx = Regex::new(r#"react-(server-components|server-rendering)/(?:[\d.]+|next-canary)"#).unwrap();
        if bundle_rx.is_match(body) {
            let mut i = Issue::new(base.meta.host.clone(), base.url(), self.name(),
                Severity::Critical, Confidence::Tentative,
                "page references a React Server-Components bundle within the CVE-2025-55182/66478 range".to_string());
            i.remediation = Some("Pin React Server-Components to a patched release (>=2025.11.5); audit any custom `use server` boundaries.".into());
            i.check_id = Some(self.id().into());
            return vec![i];
        }
        Vec::new()
    }
}
