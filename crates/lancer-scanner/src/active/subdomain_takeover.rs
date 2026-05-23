//! Subdomain-takeover fingerprinting against the live response.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

pub struct SubdomainTakeoverCheck;

/// Each entry: (provider, response-body fingerprint).
const FINGERPRINTS: &[(&str, &str)] = &[
    ("GitHub Pages", "There isn't a GitHub Pages site here."),
    ("Heroku", "No such app"),
    ("AWS S3", "NoSuchBucket"),
    ("AWS S3", "The specified bucket does not exist"),
    ("Fastly", "Fastly error: unknown domain"),
    ("Surge", "project not found"),
    ("Bitbucket", "Repository not found"),
    ("Tumblr", "There's nothing here."),
    ("WordPress", "Do you want to register"),
    ("Shopify", "Sorry, this shop is currently unavailable"),
    ("Squarespace", "No Such Account"),
    ("Tilda", "Please renew your subscription"),
    ("Pantheon", "The gods are wise, but do not know of the site which you seek"),
    ("Unbounce", "The requested URL was not found on this server"),
    ("Cloudfront", "Bad request: ERROR: The request could not be satisfied"),
    ("Netlify", "Not Found - Request ID"),
    ("Vercel", "The deployment could not be found"),
];

#[async_trait]
impl ActiveCheck for SubdomainTakeoverCheck {
    fn id(&self) -> &'static str {
        "active.subdomain_takeover"
    }
    fn name(&self) -> &'static str {
        "Possible subdomain takeover"
    }
    async fn run(
        &self,
        client: &HttpClient,
        base: &HttpRequest,
        _point: &InsertionPoint,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        let Ok(resp) = client.send(base).await else { return issues };
        let body = resp.body_text().unwrap_or("");
        for (provider, fp) in FINGERPRINTS {
            if body.contains(fp) {
                let mut i = Issue::new(
                    base.meta.host.clone(),
                    base.url(),
                    self.name(),
                    Severity::High,
                    Confidence::Tentative,
                    format!("response body matches a known `{provider}` takeover fingerprint"),
                );
                i.remediation = Some(
                    "Verify DNS still points to a live resource on the cited provider; remove dangling records.".into(),
                );
                i.check_id = Some(self.id().into());
                issues.push(i);
                break;
            }
        }
        issues
    }
}
