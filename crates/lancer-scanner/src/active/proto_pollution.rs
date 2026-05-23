//! Server-side prototype pollution probe (JSON-bodied endpoints).

use async_trait::async_trait;
use bytes::Bytes;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;
use uuid::Uuid;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

pub struct ProtoPollutionCheck;

#[async_trait]
impl ActiveCheck for ProtoPollutionCheck {
    fn id(&self) -> &'static str { "active.proto_pollution" }
    fn name(&self) -> &'static str { "Server-side prototype pollution" }
    async fn run(&self, client: &HttpClient, base: &HttpRequest, _point: &InsertionPoint) -> Vec<Issue> {
        let ct = base.header("Content-Type").unwrap_or("");
        if !ct.contains("json") { return Vec::new(); }
        let canary = format!("lancer_pp_{}", Uuid::new_v4().simple());
        // Two pollution payloads: __proto__ and constructor.prototype.
        for shape in ["{\"__proto__\":{\"lancer_canary\":\"%C%\"}}", "{\"constructor\":{\"prototype\":{\"lancer_canary\":\"%C%\"}}}"] {
            let body = shape.replace("%C%", &canary);
            let mut req = base.clone();
            req.body = Bytes::from(body);
            req.set_header("Content-Length", req.body.len().to_string());
            if client.send(&req).await.is_err() {
                continue;
            }
            // Follow-up GET on the same path — if pollution stuck, the canary
            // may leak into later responses (e.g., via an unspecified-property
            // read).
            let mut probe = base.clone();
            probe.method = lancer_core::SerializableMethod::from("GET");
            probe.body = Bytes::new();
            if let Ok(resp) = client.send(&probe).await {
                if resp.body_text().unwrap_or("").contains(&canary) {
                    let mut i = Issue::new(base.meta.host.clone(), base.url(), self.name(),
                        Severity::High, Confidence::Firm,
                        "prototype-pollution canary survived into a subsequent GET".to_string());
                    i.remediation = Some("Use Object.create(null) for parsed JSON; freeze Object.prototype; sanitise __proto__/constructor keys.".into());
                    i.check_id = Some(self.id().into());
                    return vec![i];
                }
            }
        }
        Vec::new()
    }
}
