//! Clickjacking — missing X-Frame-Options / frame-ancestors.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

pub struct ClickjackingCheck;

#[async_trait]
impl ActiveCheck for ClickjackingCheck {
    fn id(&self) -> &'static str { "active.clickjacking" }
    fn name(&self) -> &'static str { "Clickjacking — framing not denied" }
    async fn run(&self, client: &HttpClient, base: &HttpRequest, _point: &InsertionPoint) -> Vec<Issue> {
        let Ok(resp) = client.send(base).await else { return Vec::new() };
        let xfo = resp.header("X-Frame-Options").unwrap_or("").to_ascii_uppercase();
        let csp = resp.header("Content-Security-Policy").unwrap_or("").to_ascii_lowercase();
        if xfo == "DENY" || xfo == "SAMEORIGIN" || csp.contains("frame-ancestors") {
            return Vec::new();
        }
        let mut i = Issue::new(base.meta.host.clone(), base.url(), self.name(), Severity::Low, Confidence::Firm,
            "response permits framing — UI redress / clickjacking possible".to_string());
        i.remediation = Some("Set X-Frame-Options: DENY or use CSP frame-ancestors 'none'.".into());
        i.check_id = Some(self.id().into());
        vec![i]
    }
}

/// "ClickBandit" — generate a clickjacking PoC HTML page for a target URL.
pub fn clickbandit_poc(target_url: &str) -> String {
    format!(r#"<!doctype html><html><head><meta charset="utf-8"><title>Lancer ClickBandit PoC</title>
<style>iframe{{position:absolute;top:0;left:0;width:100%;height:100%;opacity:0.5;}}
button{{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);z-index:2;}}</style></head>
<body><iframe src="{target_url}"></iframe>
<button onclick="alert('User has been duped into clicking on the iframe behind this button')">Click me!</button>
</body></html>"#)
}
