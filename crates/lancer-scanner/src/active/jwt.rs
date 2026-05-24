//! JWT analysis: alg=none, weak HS secret detection, kid traversal, jku/jwk tricks.

use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;
use once_cell::sync::Lazy;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

static WEAK_SECRETS: Lazy<Arc<Vec<&'static str>>> = Lazy::new(|| {
    Arc::new(vec![
        "", "secret", "password", "admin", "changeit", "1234", "test", "jwt", "key", "default",
        "lancer", "hunter2", "p@ssw0rd",
    ])
});

pub struct JwtCheck;

#[async_trait]
impl ActiveCheck for JwtCheck {
    fn id(&self) -> &'static str {
        "active.jwt"
    }
    fn name(&self) -> &'static str {
        "JWT misconfiguration"
    }
    async fn run(
        &self,
        _client: &HttpClient,
        base: &HttpRequest,
        point: &InsertionPoint,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        let candidate = collect_candidate(base, point);
        let Some(token) = candidate else { return issues };
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return issues;
        }
        let header = match general_purpose::URL_SAFE_NO_PAD.decode(parts[0]) {
            Ok(b) => b,
            Err(_) => return issues,
        };
        let header_json: serde_json::Value = match serde_json::from_slice(&header) {
            Ok(v) => v,
            Err(_) => return issues,
        };
        let alg = header_json["alg"].as_str().unwrap_or("");
        let kid = header_json["kid"].as_str();
        let jku = header_json["jku"].as_str();
        let jwk = header_json["jwk"].clone();

        if alg.eq_ignore_ascii_case("none") {
            issues.push(jwt_issue(
                base,
                "JWT alg=none",
                Severity::Critical,
                Confidence::Firm,
                "token header declares alg=none — server may accept unsigned tokens".into(),
            ));
        }
        if let Some(kid) = kid {
            if kid.contains("..") || kid.contains('/') || kid.contains('\\') {
                issues.push(jwt_issue(
                    base,
                    "JWT kid path traversal",
                    Severity::High,
                    Confidence::Tentative,
                    format!("kid `{kid}` contains path-traversal characters"),
                ));
            }
        }
        if jku.is_some() {
            issues.push(jwt_issue(
                base,
                "JWT jku header present",
                Severity::Medium,
                Confidence::Tentative,
                "token specifies a jku — verify server validates jku domain against allow-list".into(),
            ));
        }
        if jwk.is_object() {
            issues.push(jwt_issue(
                base,
                "JWT jwk header present",
                Severity::Medium,
                Confidence::Tentative,
                "token embeds a jwk — server should never trust a key from the token itself".into(),
            ));
        }
        // Weak HS256 secret heuristic (offline)
        if alg.eq_ignore_ascii_case("HS256") || alg.eq_ignore_ascii_case("HS512") {
            if let Some(cracked) = try_weak_hs(&token, &WEAK_SECRETS) {
                issues.push(jwt_issue(
                    base,
                    "JWT signed with a weak HS secret",
                    Severity::Critical,
                    Confidence::Firm,
                    format!("HS secret recovered from a common-passwords list: `{cracked}`"),
                ));
            }
        }
        issues
    }
}

fn collect_candidate(req: &HttpRequest, point: &InsertionPoint) -> Option<String> {
    // Prefer the Authorization: Bearer xxx header.
    if let Some(auth) = req.header("Authorization") {
        if let Some(rest) = auth.strip_prefix("Bearer ") {
            return Some(rest.to_string());
        }
    }
    // Otherwise check if the insertion point itself smells like a JWT.
    if point.original_value.matches('.').count() == 2 && point.original_value.len() > 30 {
        return Some(point.original_value.clone());
    }
    None
}

fn try_weak_hs(token: &str, dict: &[&str]) -> Option<String> {
    use hmac::{Hmac, Mac};
    use sha2::{Sha256, Sha512};
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = general_purpose::URL_SAFE_NO_PAD.decode(parts[2]).ok()?;
    let header = general_purpose::URL_SAFE_NO_PAD.decode(parts[0]).ok()?;
    let header_json: serde_json::Value = serde_json::from_slice(&header).ok()?;
    let alg = header_json["alg"].as_str().unwrap_or("HS256");
    for s in dict {
        match alg {
            "HS512" => {
                if let Ok(mut mac) = <Hmac<Sha512>>::new_from_slice(s.as_bytes()) {
                    mac.update(signing_input.as_bytes());
                    if mac.verify_slice(&sig).is_ok() {
                        return Some(s.to_string());
                    }
                }
            }
            _ => {
                if let Ok(mut mac) = <Hmac<Sha256>>::new_from_slice(s.as_bytes()) {
                    mac.update(signing_input.as_bytes());
                    if mac.verify_slice(&sig).is_ok() {
                        return Some(s.to_string());
                    }
                }
            }
        }
    }
    None
}

fn jwt_issue(base: &HttpRequest, name: &str, sev: Severity, conf: Confidence, desc: String) -> Issue {
    let mut i = Issue::new(base.meta.host.clone(), base.url(), name, sev, conf, desc);
    i.remediation = Some(
        "Pin the expected alg server-side; verify signatures with a strong secret/asymmetric key; ignore client-supplied jku/jwk/kid as trust input.".into(),
    );
    i.check_id = Some("active.jwt".into());
    i
}
