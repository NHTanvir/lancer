//! BChecks DSL — a small declarative scan-check language.
//!
//! Files look like:
//!
//! ```yaml
//! id: lancer.bcheck.example
//! name: Sample BCheck
//! severity: medium
//! confidence: firm
//! when:
//!   url_contains: /admin
//! probes:
//!   - method: GET
//!     headers:
//!       X-Lancer: yes
//!     expect_status: [200, 302]
//!     expect_body_contains: "Welcome admin"
//! ```
//!
//! The runner is intentionally simple: no flow control, no expressions. Power
//! users who need anything more than literal/regex matching should drop down
//! to a Rhai script in `lancer-script`.

use anyhow::{anyhow, Result};
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BCheck {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub confidence: String,
    pub remediation: Option<String>,
    #[serde(default)]
    pub when: Option<BCheckWhen>,
    pub probes: Vec<BCheckProbe>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BCheckWhen {
    pub url_contains: Option<String>,
    pub method: Option<String>,
    pub mime: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BCheckProbe {
    pub method: Option<String>,
    pub path_suffix: Option<String>,
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    pub body: Option<String>,
    pub expect_status: Option<Vec<u16>>,
    pub expect_body_contains: Option<String>,
    pub expect_body_regex: Option<String>,
    pub expect_header: Option<ExpectHeader>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectHeader {
    pub name: String,
    pub value_contains: Option<String>,
    pub value_regex: Option<String>,
}

impl BCheck {
    pub fn parse(yaml: &str) -> Result<Self> {
        let parsed: Self = serde_yaml::from_str(yaml)?;
        Ok(parsed)
    }

    pub fn applies_to(&self, base: &HttpRequest) -> bool {
        let Some(w) = &self.when else { return true };
        if let Some(s) = &w.url_contains {
            if !base.url().contains(s) {
                return false;
            }
        }
        if let Some(m) = &w.method {
            if !base.method.as_str().eq_ignore_ascii_case(m) {
                return false;
            }
        }
        true
    }

    pub async fn run(&self, client: &HttpClient, base: &HttpRequest) -> Result<Vec<Issue>> {
        let mut issues = Vec::new();
        if !self.applies_to(base) {
            return Ok(issues);
        }
        for probe in &self.probes {
            let mut req = base.clone();
            if let Some(m) = &probe.method {
                req.method = lancer_core::SerializableMethod::from(m.as_str());
            }
            if let Some(p) = &probe.path_suffix {
                let (path_only, query) = match req.path.split_once('?') {
                    Some((p, q)) => (p.to_string(), Some(q.to_string())),
                    None => (req.path.clone(), None),
                };
                req.path = match query {
                    Some(q) => format!("{path_only}{p}?{q}"),
                    None => format!("{path_only}{p}"),
                };
            }
            for (n, v) in &probe.headers {
                req.set_header(n, v.clone());
            }
            if let Some(b) = &probe.body {
                req.body = bytes::Bytes::from(b.clone());
            }
            let resp = client.send(&req).await?;
            if !matches_probe(probe, &resp) {
                continue;
            }
            let severity = Severity::parse(&self.severity).unwrap_or(Severity::Info);
            let confidence = Confidence::parse(&self.confidence).unwrap_or(Confidence::Tentative);
            let mut i = Issue::new(
                base.meta.host.clone(),
                base.url(),
                self.name.clone(),
                severity,
                confidence,
                format!("BCheck `{}` matched", self.id),
            );
            i.remediation = self.remediation.clone();
            i.check_id = Some(self.id.clone());
            issues.push(i);
            break;
        }
        Ok(issues)
    }
}

fn matches_probe(probe: &BCheckProbe, resp: &lancer_core::HttpResponse) -> bool {
    if let Some(statuses) = &probe.expect_status {
        if !statuses.contains(&resp.status) {
            return false;
        }
    }
    let body = resp.body_text().unwrap_or("");
    if let Some(s) = &probe.expect_body_contains {
        if !body.contains(s) {
            return false;
        }
    }
    if let Some(rx) = &probe.expect_body_regex {
        match regex::Regex::new(rx) {
            Ok(r) if r.is_match(body) => {}
            _ => return false,
        }
    }
    if let Some(eh) = &probe.expect_header {
        let v = resp.header(&eh.name).unwrap_or("");
        if let Some(s) = &eh.value_contains {
            if !v.contains(s) {
                return false;
            }
        }
        if let Some(rx) = &eh.value_regex {
            match regex::Regex::new(rx) {
                Ok(r) if r.is_match(v) => {}
                _ => return false,
            }
        }
    }
    true
}

/// Library of BChecks loaded from a directory.
#[derive(Default)]
pub struct BCheckLibrary {
    pub checks: Vec<BCheck>,
}

impl BCheckLibrary {
    pub fn from_dir(dir: &std::path::Path) -> Result<Self> {
        let mut checks = Vec::new();
        if !dir.exists() {
            return Ok(Self::default());
        }
        for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
            if entry.file_type().is_file() {
                let p = entry.path();
                if matches!(p.extension().and_then(|s| s.to_str()), Some("yaml" | "yml" | "bcheck")) {
                    let body = std::fs::read_to_string(p)?;
                    match BCheck::parse(&body) {
                        Ok(c) => checks.push(c),
                        Err(e) => tracing::warn!("failed to parse {}: {e}", p.display()),
                    }
                }
            }
        }
        Ok(Self { checks })
    }

    pub async fn run_all(&self, client: &HttpClient, base: &HttpRequest) -> Vec<Issue> {
        let mut all = Vec::new();
        for c in &self.checks {
            if let Ok(mut found) = c.run(client, base).await {
                all.append(&mut found);
            }
        }
        all
    }
}

#[allow(dead_code)]
fn _assert() {
    // Just here to force `anyhow` import to stay even if unused.
    let _: Result<()> = Err(anyhow!("x"));
}
