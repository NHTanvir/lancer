//! Autorize — authorization-issue detection.
//!
//! Replays each request with a *different* identity (no cookie, low-privilege
//! cookie) and compares the response. Differences in shape (status / length)
//! suggest authz controls are in place; identical responses suggest they
//! aren't.

use anyhow::Result;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use serde::{Deserialize, Serialize};

use crate::client::HttpClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutorizeConfig {
    /// Cookie header value to substitute for "low-privilege user".
    pub low_priv_cookie: Option<String>,
    /// Cookie header value to substitute for "anonymous user".
    pub anon_cookie: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AuthzVerdict {
    Enforced,
    BypassWithLowPriv,
    BypassWithAnon,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutorizeReport {
    pub verdict: AuthzVerdict,
    pub original_status: u16,
    pub low_priv_status: Option<u16>,
    pub anon_status: Option<u16>,
}

pub async fn audit(
    client: &HttpClient,
    base: &HttpRequest,
    cfg: &AutorizeConfig,
) -> Result<AutorizeReport> {
    let original = client.send(base).await?;
    let mut low_priv_status = None;
    let mut anon_status = None;
    let mut bypass_low = false;
    let mut bypass_anon = false;

    if let Some(cookie) = &cfg.low_priv_cookie {
        let mut r = base.clone();
        r.set_header("Cookie", cookie.clone());
        let resp = client.send(&r).await?;
        low_priv_status = Some(resp.status);
        if (200..300).contains(&resp.status)
            && (resp.body.len() as i64 - original.body.len() as i64).abs() < 64
        {
            bypass_low = true;
        }
    }
    if let Some(cookie) = &cfg.anon_cookie {
        let mut r = base.clone();
        if cookie.is_empty() {
            r.remove_header("Cookie");
            r.remove_header("Authorization");
        } else {
            r.set_header("Cookie", cookie.clone());
        }
        let resp = client.send(&r).await?;
        anon_status = Some(resp.status);
        if (200..300).contains(&resp.status)
            && (resp.body.len() as i64 - original.body.len() as i64).abs() < 64
        {
            bypass_anon = true;
        }
    }

    let verdict = if bypass_anon {
        AuthzVerdict::BypassWithAnon
    } else if bypass_low {
        AuthzVerdict::BypassWithLowPriv
    } else if low_priv_status.is_some() || anon_status.is_some() {
        AuthzVerdict::Enforced
    } else {
        AuthzVerdict::Inconclusive
    };
    Ok(AutorizeReport {
        verdict,
        original_status: original.status,
        low_priv_status,
        anon_status,
    })
}

pub fn report_to_issue(base: &HttpRequest, r: &AutorizeReport) -> Option<Issue> {
    match r.verdict {
        AuthzVerdict::BypassWithAnon => Some(make(
            base,
            "Broken access control — anonymous bypass",
            Severity::High,
            Confidence::Firm,
            "anonymous request returned an indistinguishable response from the authenticated one",
        )),
        AuthzVerdict::BypassWithLowPriv => Some(make(
            base,
            "Broken access control — privilege escalation",
            Severity::High,
            Confidence::Firm,
            "low-privilege identity returned an indistinguishable response from the privileged one",
        )),
        _ => None,
    }
}

fn make(base: &HttpRequest, name: &str, sev: Severity, conf: Confidence, desc: &str) -> Issue {
    let mut i = Issue::new(base.meta.host.clone(), base.url(), name, sev, conf, desc.to_string());
    i.remediation = Some(
        "Enforce server-side authorisation on every request, keyed off authenticated identity rather than client-supplied IDs."
            .into(),
    );
    i.check_id = Some("tools.autorize".into());
    i
}
