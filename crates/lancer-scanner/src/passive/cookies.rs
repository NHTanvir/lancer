//! Cookie security-flag analysis (Secure / HttpOnly / SameSite).

use async_trait::async_trait;
use lancer_core::{HttpRequest, HttpResponse};
use lancer_storage::issues::{Confidence, Issue, Severity};

use crate::PassiveCheck;

pub struct CookieFlagCheck;

#[async_trait]
impl PassiveCheck for CookieFlagCheck {
    fn id(&self) -> &'static str {
        "passive.cookie_flags"
    }
    fn name(&self) -> &'static str {
        "Cookie set without security flags"
    }
    async fn check(&self, request: &HttpRequest, response: &HttpResponse) -> Vec<Issue> {
        let mut issues = Vec::new();
        let is_https = request.meta.scheme == "https";
        for h in &response.headers {
            if !h.name.eq_ignore_ascii_case("Set-Cookie") {
                continue;
            }
            let value = &h.value;
            let cookie_name = value
                .split(';')
                .next()
                .and_then(|s| s.split_once('='))
                .map(|(n, _)| n.trim().to_string())
                .unwrap_or_default();
            let mut secure = false;
            let mut http_only = false;
            let mut same_site_present = false;
            for attr in value.split(';').skip(1) {
                let attr = attr.trim();
                if attr.eq_ignore_ascii_case("secure") {
                    secure = true;
                } else if attr.eq_ignore_ascii_case("httponly") {
                    http_only = true;
                } else if let Some(head) = attr.get(..8) {
                    // matches `SameSite` or `SameSite=Lax`
                    if head.eq_ignore_ascii_case("samesite") {
                        let rest = &attr[8..];
                        if rest.is_empty() || rest.starts_with('=') {
                            same_site_present = true;
                        }
                    }
                }
            }
            if !secure && is_https {
                issues.push(super::issue(
                    "Cookie without Secure flag",
                    Severity::Low,
                    Confidence::Firm,
                    request,
                    format!("`{cookie_name}` set over HTTPS without the `Secure` flag"),
                    Some("Add the Secure attribute to the Set-Cookie header."),
                ));
            }
            if !http_only && looks_session_like(&cookie_name) {
                issues.push(super::issue(
                    "Cookie without HttpOnly flag",
                    Severity::Low,
                    Confidence::Tentative,
                    request,
                    format!("session-like cookie `{cookie_name}` lacks HttpOnly"),
                    Some("Add HttpOnly to session cookies to mitigate XSS impact."),
                ));
            }
            if !same_site_present {
                issues.push(super::issue(
                    "Cookie without SameSite",
                    Severity::Info,
                    Confidence::Tentative,
                    request,
                    format!("`{cookie_name}` has no SameSite attribute"),
                    Some("Set SameSite to Lax or Strict where possible."),
                ));
            }
        }
        issues
    }
}

fn looks_session_like(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "session", "sess", "sid", "auth", "token", "jwt", "phpsessid", "asp.net_sessionid",
        "jsessionid", "csrftoken",
    ]
    .iter()
    .any(|n| lower.contains(n))
}
