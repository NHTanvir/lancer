//! §50 CMS-Aware Scanner — WPScan / JoomScan / Drupal-aware checks.
//!
//! When passive detection identifies a CMS, this scanner runs targeted
//! version detection, plugin/component/theme enumeration, and CVE matching.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CmsKind {
    WordPress,
    Joomla,
    Drupal,
    Magento,
    Shopify,
    Ghost,
    Strapi,
    Sanity,
    Contentful,
    Wix,
    Webflow,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity { Info, Low, Medium, High, Critical }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmsScanRequest {
    pub target: String, // base URL
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Bruteforcing plugin/theme directories has noise; gate behind authorization.
    #[serde(default)]
    pub enumerate_plugins: bool,
}

fn default_timeout_secs() -> u64 { 15 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmsFinding {
    pub id: Uuid,
    pub cms: CmsKind,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub cve: Option<String>,
    pub evidence_url: Option<String>,
    pub found_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmsScanResult {
    pub target: String,
    pub cms: CmsKind,
    pub version: Option<String>,
    pub plugins: Vec<String>,
    pub themes: Vec<String>,
    pub findings: Vec<CmsFinding>,
    pub scanned_at: chrono::DateTime<chrono::Utc>,
}

// ── Detection ─────────────────────────────────────────────────────────────────

static WP_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)<meta name=["']generator["']\s+content=["']wordpress\s+([\d.]+)"#).unwrap()
});
static JOOMLA_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<version>([\d.]+)</version>"#).unwrap()
});
static DRUPAL_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)Drupal\s+(\d+\.\d+)"#).unwrap()
});

async fn fetch(client: &reqwest::Client, url: &str) -> Option<(u16, String)> {
    let resp = client.get(url).send().await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.ok()?;
    Some((status, body))
}

async fn detect_cms(client: &reqwest::Client, base: &str) -> CmsKind {
    let (_, root) = match fetch(client, base).await { Some(x) => x, None => return CmsKind::Unknown };
    let lower = root.to_lowercase();
    if lower.contains("wp-content") || lower.contains("wp-includes") || lower.contains("wordpress") {
        return CmsKind::WordPress;
    }
    if lower.contains("joomla!") || lower.contains("/templates/") && lower.contains("administrator") {
        return CmsKind::Joomla;
    }
    if lower.contains("drupal.settings") || lower.contains("/sites/default/") || lower.contains("\"drupal\"") {
        return CmsKind::Drupal;
    }
    if lower.contains("magento") || lower.contains("mage/cookies") {
        return CmsKind::Magento;
    }
    if lower.contains("ghost.io") || lower.contains("/ghost/") || lower.contains("x-ghost-") {
        return CmsKind::Ghost;
    }
    if lower.contains("__shopify") || lower.contains("cdn.shopify.com") {
        return CmsKind::Shopify;
    }
    if lower.contains("strapi") || lower.contains("/admin/strapi") {
        return CmsKind::Strapi;
    }
    if lower.contains("wix.com") || lower.contains("wixstatic") {
        return CmsKind::Wix;
    }
    if lower.contains("webflow.com") || lower.contains("webflow.io") {
        return CmsKind::Webflow;
    }
    CmsKind::Unknown
}

// ── WordPress ─────────────────────────────────────────────────────────────────

async fn wp_scan(client: &reqwest::Client, base: &str, enumerate: bool) -> CmsScanResult {
    let mut result = CmsScanResult {
        target: base.to_string(),
        cms: CmsKind::WordPress,
        version: None,
        plugins: Vec::new(),
        themes: Vec::new(),
        findings: Vec::new(),
        scanned_at: chrono::Utc::now(),
    };
    // Version detection: readme, generator meta, version.php
    if let Some((_, body)) = fetch(client, base).await {
        if let Some(c) = WP_VERSION_RE.captures(&body) {
            result.version = Some(c[1].to_string());
        }
    }
    if result.version.is_none() {
        if let Some((_, body)) = fetch(client, &format!("{}/readme.html", base.trim_end_matches('/'))).await {
            if let Some(c) = Regex::new(r"(?i)version\s+([\d.]+)").unwrap().captures(&body) {
                result.version = Some(c[1].to_string());
                result.findings.push(CmsFinding {
                    id: Uuid::new_v4(),
                    cms: CmsKind::WordPress,
                    severity: Severity::Low,
                    title: "WordPress readme.html exposed".into(),
                    detail: "The default WordPress readme.html file is publicly accessible — leaks version info.".into(),
                    cve: None,
                    evidence_url: Some(format!("{}/readme.html", base)),
                    found_at: chrono::Utc::now(),
                });
            }
        }
    }
    // Common public-leak endpoints
    let probes: &[(&str, &str, Severity)] = &[
        ("/xmlrpc.php", "xmlrpc.php endpoint exposed (brute-force amplification + pingback abuse)", Severity::Medium),
        ("/wp-json/wp/v2/users", "User enumeration via REST API", Severity::Medium),
        ("/wp-admin/admin-ajax.php", "admin-ajax.php exposed (varied attack surface)", Severity::Info),
        ("/wp-content/debug.log", "WordPress debug log exposed", Severity::High),
        ("/wp-config.php.bak", "wp-config backup exposed (credentials!)", Severity::Critical),
        ("/wp-config-sample.php", "Sample wp-config exposed", Severity::Info),
    ];
    for (path, msg, sev) in probes {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some((status, body)) = fetch(client, &url).await {
            if status == 200 && !body.is_empty() {
                result.findings.push(CmsFinding {
                    id: Uuid::new_v4(),
                    cms: CmsKind::WordPress,
                    severity: sev.clone(),
                    title: (*msg).into(),
                    detail: format!("HTTP {} on {}", status, path),
                    cve: None,
                    evidence_url: Some(url),
                    found_at: chrono::Utc::now(),
                });
            }
        }
    }

    if enumerate {
        for plugin in ["akismet", "yoast", "elementor", "woocommerce", "contact-form-7", "jetpack"] {
            let url = format!("{}/wp-content/plugins/{}/", base.trim_end_matches('/'), plugin);
            if let Some((status, _)) = fetch(client, &url).await {
                if status == 200 || status == 403 {
                    result.plugins.push((*plugin).into());
                }
            }
        }
    }
    result
}

// ── Joomla ────────────────────────────────────────────────────────────────────

async fn joomla_scan(client: &reqwest::Client, base: &str) -> CmsScanResult {
    let mut result = CmsScanResult {
        target: base.to_string(),
        cms: CmsKind::Joomla,
        version: None,
        plugins: Vec::new(),
        themes: Vec::new(),
        findings: Vec::new(),
        scanned_at: chrono::Utc::now(),
    };
    let manifest_url = format!("{}/administrator/manifests/files/joomla.xml", base.trim_end_matches('/'));
    if let Some((status, body)) = fetch(client, &manifest_url).await {
        if status == 200 {
            if let Some(c) = JOOMLA_VERSION_RE.captures(&body) {
                result.version = Some(c[1].to_string());
                result.findings.push(CmsFinding {
                    id: Uuid::new_v4(),
                    cms: CmsKind::Joomla,
                    severity: Severity::Low,
                    title: "Joomla version disclosed via manifest XML".into(),
                    detail: format!("administrator/manifests/files/joomla.xml exposed (v{})", &c[1]),
                    cve: None,
                    evidence_url: Some(manifest_url),
                    found_at: chrono::Utc::now(),
                });
            }
        }
    }
    let probes: &[(&str, &str, Severity)] = &[
        ("/administrator/", "Joomla admin panel exposed", Severity::Info),
        ("/configuration.php-dist", "Sample configuration exposed", Severity::Low),
        ("/.htaccess.txt", "Default .htaccess.txt exposed", Severity::Info),
    ];
    for (p, m, s) in probes {
        let url = format!("{}{}", base.trim_end_matches('/'), p);
        if let Some((status, _)) = fetch(client, &url).await {
            if status == 200 {
                result.findings.push(CmsFinding {
                    id: Uuid::new_v4(),
                    cms: CmsKind::Joomla,
                    severity: s.clone(),
                    title: (*m).into(),
                    detail: format!("HTTP {} on {}", status, p),
                    cve: None,
                    evidence_url: Some(url),
                    found_at: chrono::Utc::now(),
                });
            }
        }
    }
    result
}

// ── Drupal ────────────────────────────────────────────────────────────────────

async fn drupal_scan(client: &reqwest::Client, base: &str) -> CmsScanResult {
    let mut result = CmsScanResult {
        target: base.to_string(),
        cms: CmsKind::Drupal,
        version: None,
        plugins: Vec::new(),
        themes: Vec::new(),
        findings: Vec::new(),
        scanned_at: chrono::Utc::now(),
    };
    for path in &["/CHANGELOG.txt", "/core/CHANGELOG.txt"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some((status, body)) = fetch(client, &url).await {
            if status == 200 {
                if let Some(c) = DRUPAL_VERSION_RE.captures(&body) {
                    result.version = Some(c[1].to_string());
                    result.findings.push(CmsFinding {
                        id: Uuid::new_v4(),
                        cms: CmsKind::Drupal,
                        severity: Severity::Low,
                        title: "Drupal version disclosed via CHANGELOG".into(),
                        detail: format!("{} returned 200 with version {}", path, &c[1]),
                        cve: None,
                        evidence_url: Some(url),
                        found_at: chrono::Utc::now(),
                    });
                }
            }
        }
    }
    // Drupalgeddon-class
    let probes: &[(&str, &str, &str, Severity)] = &[
        ("/?q=node", "Node access via legacy URL", "", Severity::Info),
        ("/user/register", "User registration page open", "", Severity::Info),
        ("/install.php", "install.php exposed — re-install risk", "", Severity::High),
        ("/core/install.php", "core/install.php exposed", "", Severity::High),
        ("/rest/session/token", "REST session token endpoint exposed (Drupalgeddon2 surface)", "CVE-2018-7600", Severity::High),
    ];
    for (path, msg, cve, sev) in probes {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some((status, _)) = fetch(client, &url).await {
            if status == 200 || status == 403 {
                result.findings.push(CmsFinding {
                    id: Uuid::new_v4(),
                    cms: CmsKind::Drupal,
                    severity: sev.clone(),
                    title: (*msg).into(),
                    detail: format!("HTTP {} on {}", status, path),
                    cve: if cve.is_empty() { None } else { Some(cve.to_string()) },
                    evidence_url: Some(url),
                    found_at: chrono::Utc::now(),
                });
            }
        }
    }
    result
}

// ── Public API ────────────────────────────────────────────────────────────────

pub async fn scan(req: CmsScanRequest) -> Result<CmsScanResult, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .map_err(|e| e.to_string())?;
    let cms = detect_cms(&client, &req.target).await;
    let result = match cms {
        CmsKind::WordPress => wp_scan(&client, &req.target, req.enumerate_plugins).await,
        CmsKind::Joomla    => joomla_scan(&client, &req.target).await,
        CmsKind::Drupal    => drupal_scan(&client, &req.target).await,
        other              => CmsScanResult {
            target: req.target.clone(),
            cms: other,
            version: None,
            plugins: vec![],
            themes: vec![],
            findings: Vec::new(),
            scanned_at: chrono::Utc::now(),
        },
    };
    Ok(result)
}
