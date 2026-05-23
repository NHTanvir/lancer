//! CRLF / header-injection check.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;

use crate::insertion::{substitute, InsertionPoint};
use crate::ActiveCheck;

pub struct CrlfCheck;

const PROBE: &str = "lancer%0d%0aX-Lancer-Injected:1";

#[async_trait]
impl ActiveCheck for CrlfCheck {
    fn id(&self) -> &'static str {
        "active.crlf"
    }
    fn name(&self) -> &'static str {
        "CRLF / header injection"
    }
    async fn run(
        &self,
        client: &HttpClient,
        base: &HttpRequest,
        point: &InsertionPoint,
    ) -> Vec<Issue> {
        let Some(req) = substitute(base, point, PROBE) else { return Vec::new() };
        let Ok(resp) = client.send(&req).await else { return Vec::new() };
        if resp.header("X-Lancer-Injected").is_some() {
            let mut i = Issue::new(
                base.meta.host.clone(),
                base.url(),
                self.name(),
                Severity::High,
                Confidence::Firm,
                "CRLF in input produced a new response header (`X-Lancer-Injected`)".to_string(),
            );
            i.remediation = Some("Strip CR/LF characters from inputs that flow into response headers.".into());
            i.notes = Some(format!("insertion point: {} ({:?})", point.name, point.location));
            i.check_id = Some(self.id().to_string());
            vec![i]
        } else {
            Vec::new()
        }
    }
}
