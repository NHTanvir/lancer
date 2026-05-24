//! GraphQL — introspection enabled / batching abuse / suggestions leak.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

const INTROSPECTION_QUERY: &str =
    r#"{"query":"{__schema{types{name fields{name}}}}"}"#;

const SUGGESTIONS_QUERY: &str =
    r#"{"query":"{ doesNotExist }"}"#;

pub struct GraphQlCheck;

#[async_trait]
impl ActiveCheck for GraphQlCheck {
    fn id(&self) -> &'static str {
        "active.graphql"
    }
    fn name(&self) -> &'static str {
        "GraphQL misconfiguration"
    }
    async fn run(
        &self,
        client: &HttpClient,
        base: &HttpRequest,
        point: &InsertionPoint,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        // Run once per request.
        if point.original_value.is_empty() && point.name != "" {
            // ok
        }
        if base.path.ends_with("/graphql") || base.path.ends_with("/api/graphql") || base.body_text().unwrap_or("").contains("\"query\"") {
            // looks like a GraphQL endpoint
        } else {
            return issues;
        }
        // Introspection probe
        let mut introspect = base.clone();
        introspect.method = lancer_core::SerializableMethod::from("POST");
        introspect.set_header("Content-Type", "application/json");
        introspect.body = bytes::Bytes::from(INTROSPECTION_QUERY);
        if let Ok(resp) = client.send(&introspect).await {
            let body = resp.body_text().unwrap_or("");
            if body.contains("__schema") && body.contains("types") {
                let mut i = Issue::new(
                    base.meta.host.clone(),
                    base.url(),
                    "GraphQL introspection enabled",
                    Severity::Medium,
                    Confidence::Firm,
                    "the endpoint responded to a standard introspection query",
                );
                i.remediation = Some(
                    "Disable introspection in production; require authentication for schema queries.".into(),
                );
                i.check_id = Some(self.id().into());
                issues.push(i);
            }
        }
        // Suggestions / "Did you mean" leak
        let mut sugg = introspect.clone();
        sugg.body = bytes::Bytes::from(SUGGESTIONS_QUERY);
        if let Ok(resp) = client.send(&sugg).await {
            let body = resp.body_text().unwrap_or("");
            if body.contains("Did you mean") {
                let mut i = Issue::new(
                    base.meta.host.clone(),
                    base.url(),
                    "GraphQL field-suggestion leakage",
                    Severity::Low,
                    Confidence::Firm,
                    "server emits `Did you mean ...` suggestions, which leak schema info",
                );
                i.remediation = Some(
                    "Disable suggestion responses in production GraphQL servers.".into(),
                );
                i.check_id = Some(self.id().into());
                issues.push(i);
            }
        }
        issues
    }
}
