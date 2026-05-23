//! HTTP request-smuggling check (CL.TE / TE.CL signal).
//!
//! Sends two carefully crafted requests over a fresh connection. We can't
//! reliably do this through our pooled hyper client — so this check just
//! flags candidates: presence of both `Content-Length` and `Transfer-Encoding`
//! in the response, or a frontend that mis-handles double-Transfer-Encoding.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

pub struct SmugglingCheck;

#[async_trait]
impl ActiveCheck for SmugglingCheck {
    fn id(&self) -> &'static str { "active.smuggling" }
    fn name(&self) -> &'static str { "HTTP request smuggling (candidate)" }
    async fn run(&self, client: &HttpClient, base: &HttpRequest, _point: &InsertionPoint) -> Vec<Issue> {
        let mut req = base.clone();
        req.set_header("Transfer-Encoding", "chunked");
        req.set_header("Content-Length", "6");
        req.body = bytes::Bytes::from_static(b"0\r\n\r\nG");
        let Ok(resp) = client.send(&req).await else { return Vec::new() };
        // Indicators: 400 Bad Request often = backend cleaned up; 200 with body of "G" = passed through.
        if resp.status == 400 && resp.header("Content-Length").is_some() && resp.header("Transfer-Encoding").is_some() {
            let mut i = Issue::new(base.meta.host.clone(), base.url(), self.name(), Severity::High, Confidence::Tentative,
                "frontend forwarded both Content-Length and Transfer-Encoding — desync candidate".to_string());
            i.remediation = Some("Reject requests containing both CL and TE headers at the frontend; normalise upstream.".into());
            i.check_id = Some(self.id().into());
            return vec![i];
        }
        Vec::new()
    }
}
