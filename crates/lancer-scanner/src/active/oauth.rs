//! OAuth / OIDC misconfiguration probes.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

pub struct OAuthCheck;

#[async_trait]
impl ActiveCheck for OAuthCheck {
    fn id(&self) -> &'static str { "active.oauth" }
    fn name(&self) -> &'static str { "OAuth / OIDC misconfiguration" }
    async fn run(&self, client: &HttpClient, base: &HttpRequest, _point: &InsertionPoint) -> Vec<Issue> {
        let mut issues = Vec::new();
        // Only run once per host — keyed off the very first request seen.
        let url = base.url();
        if !(url.contains("/oauth") || url.contains("/authorize") || url.contains("/login")) {
            return issues;
        }

        // Probe: well-known discovery doc accessible.
        let host_root = format!("{}://{}", base.meta.scheme, base.host_with_port());
        let discovery = format!("{host_root}/.well-known/openid-configuration");
        if let Ok(req) = HttpRequest::builder("GET", &discovery) {
            if let Ok(resp) = client.send(&req).await {
                if resp.status == 200 && resp.body_text().unwrap_or("").contains("authorization_endpoint") {
                    issues.push(simple("OpenID discovery exposed",
                        Severity::Info, Confidence::Firm,
                        "OIDC `.well-known/openid-configuration` is reachable — confirm it's intentional",
                        base));
                }
            }
        }

        // Probe: response_type=token (implicit flow, deprecated).
        let implicit = format!("{}{}response_type=token&redirect_uri=https://evil.example.com",
            base.url(),
            if base.path.contains('?') { "&" } else { "?" });
        if let Ok(req) = HttpRequest::builder("GET", &implicit) {
            if let Ok(resp) = client.send(&req).await {
                let loc = resp.header("Location").unwrap_or("");
                if loc.contains("evil.example.com") {
                    issues.push(simple("OAuth open redirect via redirect_uri",
                        Severity::High, Confidence::Firm,
                        "server redirected to attacker-controlled redirect_uri",
                        base));
                }
            }
        }
        issues
    }
}

fn simple(name: &str, sev: Severity, conf: Confidence, desc: &str, base: &HttpRequest) -> Issue {
    let mut i = Issue::new(base.meta.host.clone(), base.url(), name, sev, conf, desc.to_string());
    i.remediation = Some("Maintain an exact-match allow-list of redirect_uris; require PKCE; disable implicit flow.".into());
    i.check_id = Some("active.oauth".into());
    i
}
