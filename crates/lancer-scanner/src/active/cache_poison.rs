//! Web-cache poisoning + deception.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;
use uuid::Uuid;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

pub struct CachePoisonCheck;

#[async_trait]
impl ActiveCheck for CachePoisonCheck {
    fn id(&self) -> &'static str { "active.cache_poison" }
    fn name(&self) -> &'static str { "Web cache poisoning / deception" }
    async fn run(&self, client: &HttpClient, base: &HttpRequest, _point: &InsertionPoint) -> Vec<Issue> {
        let mut issues = Vec::new();

        // Cache deception: append a static-looking path suffix and see if the
        // response leaks authenticated content while being cached.
        let canary = format!("lancer-{}.css", Uuid::new_v4().simple());
        let mut req = base.clone();
        req.path = format!("{}/{canary}", req.path.trim_end_matches('/'));
        if let Ok(resp) = client.send(&req).await {
            let cache_hdr = resp.header("X-Cache").or_else(|| resp.header("Cf-Cache-Status")).or_else(|| resp.header("Age"));
            if let Some(c) = cache_hdr {
                let mut i = Issue::new(base.meta.host.clone(), base.url(), "Web cache deception",
                    Severity::Medium, Confidence::Tentative,
                    format!("appending `.css` got a cached response (`{c}`) — verify auth content is being cached"));
                i.remediation = Some("Don't trust the URL path for cache keys; cache only responses with sanitised headers.".into());
                i.check_id = Some(self.id().into());
                issues.push(i);
            }
        }

        // Cache poisoning: inject an unkeyed header (X-Forwarded-Host) and check for reflection.
        let evil = "evil.example.com";
        let mut req = base.clone();
        req.set_header("X-Forwarded-Host", evil);
        if let Ok(resp) = client.send(&req).await {
            let body = resp.body_text().unwrap_or("");
            if body.contains(evil) || resp.header("Location").unwrap_or("").contains(evil) {
                let mut i = Issue::new(base.meta.host.clone(), base.url(), "Cache poisoning via X-Forwarded-Host",
                    Severity::High, Confidence::Tentative,
                    "unkeyed header X-Forwarded-Host was reflected — caches downstream may serve poisoned content".to_string());
                i.remediation = Some("Either include unkeyed headers in the cache key, or strip them at the cache layer.".into());
                i.check_id = Some(self.id().into());
                issues.push(i);
            }
        }
        issues
    }
}
