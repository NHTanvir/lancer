//! Missing / weak security headers.

use async_trait::async_trait;
use lancer_core::{HttpRequest, HttpResponse};
use lancer_storage::issues::{Confidence, Issue, Severity};

use crate::PassiveCheck;

pub struct SecurityHeaderCheck;

#[async_trait]
impl PassiveCheck for SecurityHeaderCheck {
    fn id(&self) -> &'static str {
        "passive.security_headers"
    }
    fn name(&self) -> &'static str {
        "Missing or weak security headers"
    }
    async fn check(&self, request: &HttpRequest, response: &HttpResponse) -> Vec<Issue> {
        let mut issues = Vec::new();
        let checks: &[(&str, &str, Severity, &str)] = &[
            (
                "Content-Security-Policy",
                "no CSP header — page is vulnerable to XSS-via-injected-resource",
                Severity::Low,
                "Set a restrictive Content-Security-Policy header.",
            ),
            (
                "Strict-Transport-Security",
                "no HSTS header on HTTPS response",
                Severity::Low,
                "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
            ),
            (
                "X-Content-Type-Options",
                "missing X-Content-Type-Options: nosniff",
                Severity::Info,
                "Add `X-Content-Type-Options: nosniff`.",
            ),
            (
                "X-Frame-Options",
                "missing X-Frame-Options header (clickjacking risk)",
                Severity::Low,
                "Add `X-Frame-Options: DENY` or `frame-ancestors 'none'` in CSP.",
            ),
            (
                "Referrer-Policy",
                "missing Referrer-Policy header",
                Severity::Info,
                "Add `Referrer-Policy: strict-origin-when-cross-origin`.",
            ),
            (
                "Permissions-Policy",
                "missing Permissions-Policy header",
                Severity::Info,
                "Set a Permissions-Policy header to lock down unused features.",
            ),
        ];
        let is_https = request.meta.scheme == "https";
        for (header, desc, sev, fix) in checks {
            if *header == "Strict-Transport-Security" && !is_https {
                continue;
            }
            if response.header(header).is_none() {
                issues.push(super::issue(
                    self.name(),
                    *sev,
                    Confidence::Firm,
                    request,
                    *desc,
                    Some(*fix),
                ));
            }
        }
        // Weak CSP (`unsafe-inline` / `unsafe-eval`)
        if let Some(csp) = response.header("Content-Security-Policy") {
            if csp.contains("unsafe-inline") || csp.contains("unsafe-eval") {
                issues.push(super::issue(
                    self.name(),
                    Severity::Low,
                    Confidence::Firm,
                    request,
                    format!("CSP allows unsafe sources: `{csp}`"),
                    Some("Remove unsafe-inline / unsafe-eval; use nonces or hashes."),
                ));
            }
        }
        issues
    }
}
