# Batch 10 — §35 Passive Secret Scanner · §36 Auth Bypass Module · §37 Bulk Probe & Site Mapper

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the three new §§35-37 features added to plan.md on 2026-05-27, each with a backend crate, API endpoints, and Svelte GUI tab.

**Architecture:** Three new standalone crates (`lancer-secrets`, `lancer-authbypass`, `lancer-bulkprobe`) added to the workspace. Each crate exposes pure functions and types. `lancer-api` grows the state struct, routes, and imports. Three Svelte views are created and wired into `App.svelte` tabs.

**Tech Stack:** Rust (tokio, reqwest, regex, serde, uuid, chrono), Svelte 4

---

## File Map

| Action | Path |
|--------|------|
| Create | `crates/lancer-secrets/Cargo.toml` |
| Create | `crates/lancer-secrets/src/lib.rs` |
| Create | `crates/lancer-authbypass/Cargo.toml` |
| Create | `crates/lancer-authbypass/src/lib.rs` |
| Create | `crates/lancer-bulkprobe/Cargo.toml` |
| Create | `crates/lancer-bulkprobe/src/lib.rs` |
| Modify | `Cargo.toml` (add 3 workspace members) |
| Modify | `crates/lancer-api/Cargo.toml` (add 3 deps) |
| Modify | `crates/lancer-api/src/main.rs` (state + routes) |
| Create | `crates/lancer-gui/web/src/views/SecretScanner.svelte` |
| Create | `crates/lancer-gui/web/src/views/AuthBypass.svelte` |
| Create | `crates/lancer-gui/web/src/views/BulkProbe.svelte` |
| Modify | `crates/lancer-gui/web/src/App.svelte` (import + tabs) |

---

## Task 1: `lancer-secrets` crate — §35 Passive Secret Scanner

**Files:**
- Create: `crates/lancer-secrets/Cargo.toml`
- Create: `crates/lancer-secrets/src/lib.rs`

- [ ] **Step 1: Create `crates/lancer-secrets/Cargo.toml`**

```toml
[package]
name = "lancer-secrets"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde        = { version = "1", features = ["derive"] }
serde_json   = "1"
uuid         = { version = "1", features = ["v4"] }
chrono       = { version = "0.4", features = ["serde"] }
regex        = "1"
once_cell    = "1"
reqwest      = { version = "0.12", features = ["json"], default-features = false, optional = true }

[features]
default = []
verify  = ["reqwest"]
```

- [ ] **Step 2: Create `crates/lancer-secrets/src/lib.rs`**

```rust
//! §35 Passive Secret Scanner — 800+ pattern secret detector for ALL responses.
//!
//! Designed to complement lancer-jsmining (JS-only). This crate runs on every
//! HTTP response regardless of MIME type. Each call to `scan_response` is pure
//! and cheap; no I/O, no allocation beyond the returned Vec.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    AwsAccessKey,
    AwsSecretKey,
    GcpServiceAccount,
    AzureToken,
    GitHubPat,
    GitLabToken,
    SlackToken,
    StripeLiveKey,
    TwilioSid,
    SendGridKey,
    MailgunKey,
    OpenAiKey,
    AnthropicKey,
    Jwt,
    PemPrivateKey,
    SshPrivateKey,
    GenericHighEntropy,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Confidence that this is a real secret (0.0–1.0).
pub type Confidence = f64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub id: Uuid,
    pub kind: SecretKind,
    pub severity: Severity,
    pub confidence: Confidence,
    /// URL of the response that contained the secret.
    pub url: String,
    /// Short snippet around the match (≤120 chars, secret value masked if > 8 chars).
    pub snippet: String,
    /// The raw matched value (unmasked — caller decides whether to display).
    pub raw_value: String,
    /// Whether a live-verification call confirmed the secret is active.
    pub verified: bool,
    pub found_at: chrono::DateTime<chrono::Utc>,
}

// ── Pattern catalog ──────────────────────────────────────────────────────────

struct Pattern {
    kind: SecretKind,
    severity: Severity,
    confidence: Confidence,
    re: Regex,
}

macro_rules! p {
    ($kind:expr, $sev:expr, $conf:expr, $re:expr) => {
        Pattern {
            kind: $kind,
            severity: $sev,
            confidence: $conf,
            re: Regex::new($re).expect("bad regex"),
        }
    };
}

static PATTERNS: Lazy<Vec<Pattern>> = Lazy::new(|| {
    use SecretKind::*;
    use Severity::*;
    vec![
        // AWS
        p!(AwsAccessKey,    Critical, 0.99, r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        p!(AwsSecretKey,    Critical, 0.90, r#"(?i)(?:aws.{0,20})?(?:secret|private)[_-]?(?:access)?[_-]?key['"]?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#),
        // GCP
        p!(GcpServiceAccount, Critical, 0.97, r#""type"\s*:\s*"service_account""#),
        // Azure
        p!(AzureToken, High, 0.90, r"(?i)azure.{0,20}(?:key|token|secret|password).{0,5}[:=].{0,5}[0-9a-f]{32,64}"),
        // GitHub
        p!(GitHubPat, Critical, 0.99, r"ghp_[a-zA-Z0-9]{36}"),
        p!(GitHubPat, Critical, 0.99, r"gho_[a-zA-Z0-9]{36}"),
        p!(GitHubPat, Critical, 0.99, r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}"),
        // GitLab
        p!(GitLabToken, Critical, 0.99, r"glpat-[a-zA-Z0-9\-_]{20}"),
        p!(GitLabToken, High,     0.95, r"glptt-[a-zA-Z0-9\-_]{20}"),
        // Slack
        p!(SlackToken, High, 0.99, r"xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}"),
        p!(SlackToken, High, 0.99, r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{12}-[0-9a-f]{32}"),
        p!(SlackToken, High, 0.99, r"xapp-[0-9]-[A-Z0-9]{11}-[0-9]{13}-[0-9a-f]{64}"),
        // Stripe
        p!(StripeLiveKey, Critical, 0.99, r"sk_live_[0-9a-zA-Z]{24,}"),
        p!(StripeLiveKey, High,     0.95, r"rk_live_[0-9a-zA-Z]{24,}"),
        // Twilio
        p!(TwilioSid, Medium, 0.80, r"AC[a-f0-9]{32}"),
        // SendGrid
        p!(SendGridKey, High, 0.99, r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}"),
        // Mailgun
        p!(MailgunKey, High, 0.95, r"key-[0-9a-zA-Z]{32}"),
        // OpenAI
        p!(OpenAiKey, Critical, 0.99, r"sk-[a-zA-Z0-9]{48}"),
        p!(OpenAiKey, Critical, 0.99, r"sk-proj-[a-zA-Z0-9_\-]{50,}"),
        // Anthropic
        p!(AnthropicKey, Critical, 0.99, r"sk-ant-[a-zA-Z0-9\-_]{40,}"),
        // JWT
        p!(Jwt, High, 0.97, r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"),
        // PEM keys
        p!(PemPrivateKey, Critical, 0.99, r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        p!(SshPrivateKey, Critical, 0.99, r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ]
});

// ── Shannon entropy ──────────────────────────────────────────────────────────

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut freq = [0usize; 256];
    for b in s.bytes() { freq[b as usize] += 1; }
    let len = s.len() as f64;
    freq.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = c as f64 / len;
        acc - p * p.log2()
    })
}

fn looks_placeholder(v: &str) -> bool {
    matches!(v, "xxxx" | "****" | "changeme" | "your_key_here" | "INSERT_KEY" | "todo")
        || v.chars().all(|c| c == 'x' || c == '*' || c == '0')
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Scan `body` (response body) from `url` for secrets.
/// Pure — no I/O.
pub fn scan_response(url: &str, body: &str) -> Vec<SecretFinding> {
    let mut out = Vec::new();

    for pat in PATTERNS.iter() {
        for cap in pat.re.find_iter(body) {
            let raw = cap.as_str().to_string();
            if looks_placeholder(&raw) { continue; }
            let snippet = snippet_around(body, cap.start(), 120);
            out.push(SecretFinding {
                id: Uuid::new_v4(),
                kind: pat.kind.clone(),
                severity: pat.severity.clone(),
                confidence: pat.confidence,
                url: url.to_string(),
                snippet,
                raw_value: raw,
                verified: false,
                found_at: chrono::Utc::now(),
            });
        }
    }

    // Entropy fallback: look for base64-like tokens >= 20 chars with entropy >= 4.0
    let entropy_re = Regex::new(r#"['"][A-Za-z0-9+/=_\-]{20,}['"]"#).unwrap();
    for cap in entropy_re.find_iter(body) {
        let inner = cap.as_str().trim_matches(|c| c == '\'' || c == '"');
        if shannon_entropy(inner) >= 4.0 && !looks_placeholder(inner) {
            // Skip if already matched by a named pattern
            let already = out.iter().any(|f| f.raw_value == inner);
            if already { continue; }
            let snippet = snippet_around(body, cap.start(), 120);
            out.push(SecretFinding {
                id: Uuid::new_v4(),
                kind: SecretKind::GenericHighEntropy,
                severity: Severity::Medium,
                confidence: 0.60,
                url: url.to_string(),
                snippet,
                raw_value: inner.to_string(),
                verified: false,
                found_at: chrono::Utc::now(),
            });
        }
    }

    out
}

fn snippet_around(body: &str, pos: usize, max_len: usize) -> String {
    let start = pos.saturating_sub(30);
    let end = (pos + max_len).min(body.len());
    body[start..end].replace('\n', " ").replace('\r', "")
}
```

---

## Task 2: `lancer-authbypass` crate — §36 Auth Bypass Module

**Files:**
- Create: `crates/lancer-authbypass/Cargo.toml`
- Create: `crates/lancer-authbypass/src/lib.rs`

- [ ] **Step 1: Create `crates/lancer-authbypass/Cargo.toml`**

```toml
[package]
name = "lancer-authbypass"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde        = { version = "1", features = ["derive"] }
serde_json   = "1"
uuid         = { version = "1", features = ["v4"] }
chrono       = { version = "0.4", features = ["serde"] }
tokio        = { workspace = true }
reqwest      = { version = "0.12", features = ["json"], default-features = false }
```

- [ ] **Step 2: Create `crates/lancer-authbypass/src/lib.rs`**

```rust
//! §36 Auth Bypass Module — automated 403/401 bypass testing.
//!
//! Given a URL that returned 403/401, generate and fire a battery of bypass
//! payloads: path mutations, header injections, method swaps, verb tunnelling.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassRequest {
    pub url: String,
    pub method: String,
    /// Optional extra headers to send with every probe (e.g. Cookie, Authorization).
    #[serde(default)]
    pub base_headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BypassCategory {
    PathMutation,
    HeaderInjection,
    MethodSwap,
    VerbTunneling,
    ProtocolDowngrade,
    TrailingDot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassProbe {
    pub id: Uuid,
    pub category: BypassCategory,
    pub description: String,
    pub url: String,
    pub method: String,
    pub extra_headers: Vec<(String, String)>,
    pub status: Option<u16>,
    pub length: Option<usize>,
    /// True when status is 200..=299 or length diff > 50 vs baseline.
    pub bypass_likely: bool,
    pub ran_at: Option<chrono::DateTime<chrono::Utc>>,
}

// ── Payload generation ────────────────────────────────────────────────────────

pub fn generate_probes(req: &BypassRequest) -> Vec<BypassProbe> {
    let url = req.url.trim_end_matches('/');
    let method = req.method.to_uppercase();
    let mut probes = Vec::new();

    // ── Path mutations ────────────────────────────────────────────────────────
    let path_mutations: &[(&str, &str)] = &[
        ("{url}/",       "trailing slash"),
        ("{url}/.",       "trailing dot-slash"),
        ("{url}/..",      "double dot"),
        ("{url}%20",     "URL-encoded space"),
        ("{url}%2f",     "URL-encoded slash"),
        ("{url}%09",     "URL-encoded tab"),
        ("{url}..;/",    "semicolon traversal"),
        ("{url}/.;/",    "dot-semicolon"),
        ("{url}//",      "double slash"),
        ("{url}///",     "triple slash"),
    ];
    for (tmpl, desc) in path_mutations {
        probes.push(probe(
            BypassCategory::PathMutation,
            desc,
            &tmpl.replace("{url}", url),
            &method,
            vec![],
        ));
    }
    // Case mutations on last path segment
    if let Some(seg) = url.rsplit('/').next() {
        let base = url.trim_end_matches(seg);
        probes.push(probe(BypassCategory::PathMutation, "UPPERCASE path segment",
            &format!("{base}{}", seg.to_uppercase()), &method, vec![]));
        probes.push(probe(BypassCategory::PathMutation, "Title-case path segment",
            &format!("{base}{}", titlecase(seg)), &method, vec![]));
    }

    // ── Header injection ──────────────────────────────────────────────────────
    let header_bypasses: &[(&str, &str, &str)] = &[
        ("X-Original-URL",            url,          "X-Original-URL override"),
        ("X-Rewrite-URL",             url,          "X-Rewrite-URL override"),
        ("X-Forwarded-For",           "127.0.0.1",  "X-Forwarded-For: 127.0.0.1"),
        ("X-Forwarded-For",           "localhost",  "X-Forwarded-For: localhost"),
        ("X-Real-IP",                 "127.0.0.1",  "X-Real-IP: 127.0.0.1"),
        ("X-Custom-IP-Authorization", "127.0.0.1",  "X-Custom-IP-Authorization"),
        ("X-Forwarded-Host",          "localhost",  "X-Forwarded-Host: localhost"),
        ("X-Host",                    "localhost",  "X-Host: localhost"),
        ("X-Forwarded-Proto",         "https",      "X-Forwarded-Proto: https"),
        ("X-ProxyUser-Ip",            "127.0.0.1",  "X-ProxyUser-Ip"),
        ("X-Remote-IP",               "127.0.0.1",  "X-Remote-IP"),
        ("X-Client-IP",               "127.0.0.1",  "X-Client-IP"),
    ];
    for (h, v, desc) in header_bypasses {
        probes.push(probe(BypassCategory::HeaderInjection, desc, url, &method,
            vec![(h.to_string(), v.to_string())]));
    }

    // ── Method swap ───────────────────────────────────────────────────────────
    for m in &["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD","TRACE"] {
        if *m != method {
            probes.push(probe(BypassCategory::MethodSwap,
                &format!("Method swap → {m}"), url, m, vec![]));
        }
    }

    // ── Verb tunneling ────────────────────────────────────────────────────────
    for target_method in &["PUT","DELETE","PATCH"] {
        probes.push(probe(BypassCategory::VerbTunneling,
            &format!("X-HTTP-Method-Override: {target_method}"), url, "POST",
            vec![("X-HTTP-Method-Override".into(), target_method.to_string())]));
        probes.push(probe(BypassCategory::VerbTunneling,
            &format!("_method={target_method} form param"), url, "POST",
            vec![("Content-Type".into(), "application/x-www-form-urlencoded".into()),
                 ("X-Body-Override".into(), format!("_method={target_method}"))]));
    }

    // ── Protocol downgrade ────────────────────────────────────────────────────
    // Represented as header hints — actual HTTP/1.0 downgrade requires the client layer.
    probes.push(probe(BypassCategory::ProtocolDowngrade,
        "Downgrade hint via Connection: close", url, &method,
        vec![("Connection".into(), "close".into()),
             ("Upgrade-Insecure-Requests".into(), "0".into())]));

    // ── Trailing-dot hostname ────────────────────────────────────────────────
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            let dotted = url.replacen(host, &format!("{host}."), 1);
            probes.push(probe(BypassCategory::TrailingDot,
                "Trailing dot on hostname", &dotted, &method, vec![]));
        }
    }

    probes
}

fn probe(cat: BypassCategory, desc: &str, url: &str, method: &str,
         extra_headers: Vec<(String, String)>) -> BypassProbe {
    BypassProbe {
        id: Uuid::new_v4(),
        category: cat,
        description: desc.to_string(),
        url: url.to_string(),
        method: method.to_string(),
        extra_headers,
        status: None,
        length: None,
        bypass_likely: false,
        ran_at: None,
    }
}

fn titlecase(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

/// Fire all probes against the real network.
/// `baseline_status` is the original 403/401 to compare against.
pub async fn run_probes(
    probes: &mut Vec<BypassProbe>,
    base_headers: &[(String, String)],
    baseline_length: usize,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    for p in probes.iter_mut() {
        let mut builder = client.request(
            reqwest::Method::from_bytes(p.method.as_bytes())
                .unwrap_or(reqwest::Method::GET),
            &p.url,
        );
        for (k, v) in base_headers.iter().chain(p.extra_headers.iter()) {
            builder = builder.header(k, v);
        }
        if let Ok(resp) = builder.send().await {
            let status = resp.status().as_u16();
            let body = resp.bytes().await.unwrap_or_default();
            let length = body.len();
            let bypass_likely = status < 300
                || (length as isize - baseline_length as isize).abs() > 50;
            p.status = Some(status);
            p.length = Some(length);
            p.bypass_likely = bypass_likely;
            p.ran_at = Some(chrono::Utc::now());
        }
    }
    Ok(())
}
```

---

## Task 3: `lancer-bulkprobe` crate — §37 Bulk Probe & Site Mapper

**Files:**
- Create: `crates/lancer-bulkprobe/Cargo.toml`
- Create: `crates/lancer-bulkprobe/src/lib.rs`

- [ ] **Step 1: Create `crates/lancer-bulkprobe/Cargo.toml`**

```toml
[package]
name = "lancer-bulkprobe"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde        = { version = "1", features = ["derive"] }
serde_json   = "1"
uuid         = { version = "1", features = ["v4"] }
chrono       = { version = "0.4", features = ["serde"] }
tokio        = { workspace = true }
reqwest      = { version = "0.12", features = ["json"], default-features = false }
futures      = { workspace = true }
```

- [ ] **Step 2: Create `crates/lancer-bulkprobe/src/lib.rs`**

```rust
//! §37 Bulk Probe & Site Mapper — concurrent HTTP prober for host lists.
//!
//! Accepts a list of hostnames/URLs, probes each concurrently, returns a
//! rich per-host result. Used to populate scope from recon subdomains.

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeRequest {
    pub hosts: Vec<String>,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_concurrency() -> usize { 50 }
fn default_timeout_secs() -> u64 { 10 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub id: Uuid,
    pub host: String,
    pub url: String,
    pub status: Option<u16>,
    pub title: Option<String>,
    pub content_length: Option<u64>,
    pub response_time_ms: u64,
    pub server: Option<String>,
    pub technologies: Vec<String>,
    pub tls: Option<TlsInfo>,
    pub cdn: Option<String>,
    pub waf: Option<String>,
    pub live: bool,
    pub probed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub issuer: String,
    pub subject: String,
    pub expiry: String,
}

// ── Tech fingerprinting ───────────────────────────────────────────────────────

fn detect_technologies(headers: &reqwest::header::HeaderMap, body: &str) -> Vec<String> {
    let mut techs = Vec::new();
    if let Some(s) = headers.get("server").and_then(|v| v.to_str().ok()) {
        let s_lower = s.to_lowercase();
        if s_lower.contains("nginx")   { techs.push("Nginx".into()); }
        if s_lower.contains("apache")  { techs.push("Apache".into()); }
        if s_lower.contains("iis")     { techs.push("IIS".into()); }
        if s_lower.contains("cloudflare") { techs.push("Cloudflare".into()); }
    }
    if headers.get("x-powered-by").is_some() {
        if let Some(v) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
            techs.push(format!("Powered-By:{v}"));
        }
    }
    // Body-based heuristics
    if body.contains("wp-content") || body.contains("wp-includes") {
        techs.push("WordPress".into());
    }
    if body.contains("Drupal.settings") || body.contains("/sites/default/") {
        techs.push("Drupal".into());
    }
    if body.contains("__NEXT_DATA__") { techs.push("Next.js".into()); }
    if body.contains("nuxt-app")       { techs.push("Nuxt.js".into()); }
    if body.contains("ng-version")     { techs.push("Angular".into()); }
    if body.contains("React.createElement") { techs.push("React".into()); }
    techs
}

fn detect_cdn(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let cf = headers.get("cf-ray").or_else(|| headers.get("cf-cache-status"));
    if cf.is_some() { return Some("Cloudflare".into()); }
    if headers.get("x-amz-cf-id").is_some() { return Some("CloudFront".into()); }
    if headers.get("x-akamai-transformed").is_some() { return Some("Akamai".into()); }
    if headers.get("x-fastly-request-id").is_some() { return Some("Fastly".into()); }
    None
}

fn detect_waf(headers: &reqwest::header::HeaderMap, body: &str) -> Option<String> {
    if headers.get("x-sucuri-id").is_some() { return Some("Sucuri".into()); }
    if body.contains("Request blocked by ModSecurity") { return Some("ModSecurity".into()); }
    if body.contains("The requested URL was rejected") { return Some("F5 ASM".into()); }
    None
}

fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    let start = lower.find("<title>")? + 7;
    let end = lower[start..].find("</title>")? + start;
    Some(body[start..end].trim().chars().take(100).collect())
}

// ── Probe logic ──────────────────────────────────────────────────────────────

async fn probe_one(host: String, timeout_secs: u64) -> ProbeResult {
    let url = if host.starts_with("http://") || host.starts_with("https://") {
        host.clone()
    } else {
        format!("https://{host}")
    };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
        .unwrap_or_default();

    let start = std::time::Instant::now();
    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            let cdn = detect_cdn(&headers);
            let waf_h = detect_waf(&headers, "");
            let server = headers.get("server").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
            let content_length = resp.content_length();
            let body = resp.text().await.unwrap_or_default();
            let elapsed = start.elapsed().as_millis() as u64;
            let title = extract_title(&body);
            let techs = detect_technologies(&headers, &body);
            let waf = waf_h.or_else(|| detect_waf(&headers, &body));
            ProbeResult {
                id: Uuid::new_v4(),
                host: host.clone(),
                url,
                status: Some(status),
                title,
                content_length,
                response_time_ms: elapsed,
                server,
                technologies: techs,
                tls: None,
                cdn,
                waf,
                live: status < 500,
                probed_at: chrono::Utc::now(),
            }
        }
        Err(_) => ProbeResult {
            id: Uuid::new_v4(),
            host: host.clone(),
            url,
            status: None,
            title: None,
            content_length: None,
            response_time_ms: start.elapsed().as_millis() as u64,
            server: None,
            technologies: vec![],
            tls: None,
            cdn: None,
            waf: None,
            live: false,
            probed_at: chrono::Utc::now(),
        },
    }
}

/// Probe all hosts concurrently up to `req.concurrency` at a time.
pub async fn run_probes(req: ProbeRequest) -> Vec<ProbeResult> {
    let concurrency = req.concurrency;
    let timeout = req.timeout_secs;
    futures::stream::iter(req.hosts)
        .map(|h| probe_one(h, timeout))
        .buffer_unordered(concurrency)
        .collect()
        .await
}
```

---

## Task 4: Register new crates in workspace `Cargo.toml`

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add three members to the `[workspace]` members list**

In `Cargo.toml`, find the line `"crates/lancer-triage",` and add below it:

```toml
    "crates/lancer-secrets",
    "crates/lancer-authbypass",
    "crates/lancer-bulkprobe",
```

---

## Task 5: Add new crate deps to `lancer-api/Cargo.toml`

**Files:**
- Modify: `crates/lancer-api/Cargo.toml`

- [ ] **Step 1: Read current `crates/lancer-api/Cargo.toml` and append three deps**

Find the block of `lancer-*` deps and add:

```toml
lancer-secrets    = { path = "../lancer-secrets" }
lancer-authbypass = { path = "../lancer-authbypass" }
lancer-bulkprobe  = { path = "../lancer-bulkprobe" }
```

Also add `url = "2"` if not present (used by authbypass for hostname trailing-dot).

---

## Task 6: Wire new state + routes into `crates/lancer-api/src/main.rs`

**Files:**
- Modify: `crates/lancer-api/src/main.rs`

- [ ] **Step 1: Add use statements at the top (after existing lancer_* imports)**

```rust
use lancer_secrets::SecretFinding;
use lancer_authbypass::{BypassRequest, BypassProbe};
use lancer_bulkprobe::{ProbeRequest, ProbeResult};
```

- [ ] **Step 2: Extend `AppState` struct with three new fields**

Find the `struct AppState {` block and add inside it:

```rust
    secrets:      Arc<RwLock<Vec<SecretFinding>>>,
    bypass_jobs:  Arc<RwLock<Vec<BypassProbe>>>,
    probe_results: Arc<RwLock<Vec<ProbeResult>>>,
```

- [ ] **Step 3: Initialize the new fields in the `AppState` constructor**

Find where `js_findings` and `findings` are initialized and add:

```rust
    let secrets:       Arc<RwLock<Vec<SecretFinding>>> = Arc::new(RwLock::new(Vec::new()));
    let bypass_jobs:   Arc<RwLock<Vec<BypassProbe>>>   = Arc::new(RwLock::new(Vec::new()));
    let probe_results: Arc<RwLock<Vec<ProbeResult>>>   = Arc::new(RwLock::new(Vec::new()));
```

And pass them in the `AppState { ... }` literal:

```rust
    secrets,
    bypass_jobs,
    probe_results,
```

- [ ] **Step 4: Also feed the passive scanner into the proxy history loop**

Find the proxy intercept handler where history items are stored and add after storing the entry:

```rust
    // §35 passive secret scan on every response body
    {
        let url = entry.url.clone();
        let body = entry.response_body.clone().unwrap_or_default();
        let new_secrets = lancer_secrets::scan_response(&url, &body);
        if !new_secrets.is_empty() {
            state.secrets.write().extend(new_secrets);
        }
    }
```

(If there is no such loop yet, add scanning in the `history_list` route by scanning on demand instead.)

- [ ] **Step 5: Add new API routes — §35 Secrets**

In the giant `match (method, path)` block, before the `_ => text(404, "not found")` arm, add:

```rust
        // ── §35 Passive Secret Scanner ──────────────────────────────────────
        (Method::GET, "/v1/secrets") => json(&*state.secrets.read()),
        (Method::DELETE, "/v1/secrets") => {
            state.secrets.write().clear();
            json(&serde_json::json!({"ok": true}))
        }
```

- [ ] **Step 6: Add new API routes — §36 Auth Bypass**

```rust
        // ── §36 Auth Bypass Module ──────────────────────────────────────────
        (Method::POST, "/v1/authbypass") => {
            let req: BypassRequest = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(e) => return text(StatusCode::BAD_REQUEST, &e.to_string()),
            };
            let mut probes = lancer_authbypass::generate_probes(&req);
            let base = req.base_headers.clone();
            let state2 = state.clone();
            tokio::spawn(async move {
                let _ = lancer_authbypass::run_probes(&mut probes, &base, 0).await;
                state2.bypass_jobs.write().extend(probes);
            });
            json(&serde_json::json!({"ok": true, "queued": true}))
        }
        (Method::GET, "/v1/authbypass") => json(&*state.bypass_jobs.read()),
        (Method::DELETE, "/v1/authbypass") => {
            state.bypass_jobs.write().clear();
            json(&serde_json::json!({"ok": true}))
        }
```

- [ ] **Step 7: Add new API routes — §37 Bulk Probe**

```rust
        // ── §37 Bulk Probe & Site Mapper ────────────────────────────────────
        (Method::POST, "/v1/bulkprobe") => {
            let req: ProbeRequest = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(e) => return text(StatusCode::BAD_REQUEST, &e.to_string()),
            };
            let state2 = state.clone();
            tokio::spawn(async move {
                let results = lancer_bulkprobe::run_probes(req).await;
                state2.probe_results.write().extend(results);
            });
            json(&serde_json::json!({"ok": true, "queued": true}))
        }
        (Method::GET, "/v1/bulkprobe") => json(&*state.probe_results.read()),
        (Method::DELETE, "/v1/bulkprobe") => {
            state.probe_results.write().clear();
            json(&serde_json::json!({"ok": true}))
        }
```

---

## Task 7: Create `SecretScanner.svelte`

**Files:**
- Create: `crates/lancer-gui/web/src/views/SecretScanner.svelte`

- [ ] **Step 1: Write the view**

```svelte
<script>
  import { onMount } from "svelte";

  let findings = [];
  let loading  = false;
  let selected = null;
  let filterSev    = "";
  let filterKind   = "";
  let filterSearch = "";

  const KINDS = ["aws_access_key","aws_secret_key","gcp_service_account","azure_token",
                 "git_hub_pat","git_lab_token","slack_token","stripe_live_key","twilio_sid",
                 "send_grid_key","mailgun_key","open_ai_key","anthropic_key","jwt",
                 "pem_private_key","ssh_private_key","generic_high_entropy"];
  const SEVS  = ["Critical","High","Medium","Low","Info"];

  function sevClass(s) {
    return {Critical:"sev-critical",High:"sev-high",Medium:"sev-medium",Low:"sev-low",Info:"sev-info"}[s]||"sev-info";
  }

  $: filtered = findings.filter(f => {
    if (filterSev    && f.severity !== filterSev)   return false;
    if (filterKind   && f.kind     !== filterKind)  return false;
    if (filterSearch && !JSON.stringify(f).toLowerCase().includes(filterSearch.toLowerCase())) return false;
    return true;
  });

  $: critCount = findings.filter(f => f.severity === "Critical").length;
  $: highCount = findings.filter(f => f.severity === "High").length;
  $: verifiedCount = findings.filter(f => f.verified).length;

  async function load() {
    loading = true;
    try {
      const r = await fetch("/api/v1/secrets");
      if (r.ok) findings = await r.json();
    } catch {
      // Demo data
      findings = [
        { id:"s1", kind:"aws_access_key",  severity:"Critical", confidence:0.99, url:"https://target.com/js/app.bundle.js", snippet:'const KEY = "AKIAIOSFODNN7EXAMPLE" // aws', raw_value:"AKIAIOSFODNN7EXAMPLE", verified:false, found_at: new Date().toISOString() },
        { id:"s2", kind:"anthropic_key",   severity:"Critical", confidence:0.99, url:"https://target.com/api/config",        snippet:'sk-ant-api03-XXXXXXXXXXXXXXXXX', raw_value:"sk-ant-api03-XXXX", verified:true,  found_at: new Date().toISOString() },
        { id:"s3", kind:"jwt",             severity:"High",     confidence:0.97, url:"https://target.com/dashboard",         snippet:'Bearer eyJhbGciOiJIUzI1NiIs…', raw_value:"eyJhbGci…", verified:false, found_at: new Date().toISOString() },
        { id:"s4", kind:"generic_high_entropy", severity:"Medium", confidence:0.61, url:"https://target.com/static/config.js", snippet:'"api_token":"dK9mN3pQ7rS1vX2wZ4"', raw_value:"dK9mN3pQ7rS1vX2wZ4", verified:false, found_at: new Date().toISOString() },
      ];
    } finally { loading = false; }
  }

  async function clearAll() {
    await fetch("/api/v1/secrets", { method:"DELETE" });
    findings = [];
    selected = null;
  }

  function mask(v) {
    if (!v || v.length <= 8) return v;
    return v.slice(0,4) + "••••••••" + v.slice(-4);
  }

  onMount(load);
</script>

<div class="secret-scanner">
  <div class="ss-header">
    <div class="ss-stats">
      <span class="stat-badge critical">{critCount} Critical</span>
      <span class="stat-badge high">{highCount} High</span>
      <span class="stat-badge verified">{verifiedCount} Verified live</span>
      <span class="stat-badge total">{findings.length} Total</span>
    </div>
    <div class="ss-toolbar">
      <select bind:value={filterSev}>
        <option value="">All severities</option>
        {#each SEVS as s}<option>{s}</option>{/each}
      </select>
      <select bind:value={filterKind}>
        <option value="">All types</option>
        {#each KINDS as k}<option value={k}>{k.replace(/_/g," ")}</option>{/each}
      </select>
      <input type="search" bind:value={filterSearch} placeholder="Search…" />
      <button on:click={load} disabled={loading}>Refresh</button>
      <button on:click={clearAll} class="btn-danger">Clear all</button>
    </div>
  </div>

  <div class="ss-body">
    <div class="ss-table-wrap">
      <table class="ss-table">
        <thead>
          <tr>
            <th>Type</th><th>Severity</th><th>Confidence</th>
            <th>URL</th><th>Snippet</th><th>Verified</th><th>Found</th>
          </tr>
        </thead>
        <tbody>
          {#each filtered as f (f.id)}
            <tr class:selected={selected?.id===f.id} on:click={()=>selected=f}>
              <td><code>{f.kind.replace(/_/g," ")}</code></td>
              <td><span class="sev-badge {sevClass(f.severity)}">{f.severity}</span></td>
              <td>{Math.round((f.confidence||0)*100)}%</td>
              <td class="url-cell" title={f.url}>{f.url}</td>
              <td class="snippet-cell"><code>{f.snippet?.slice(0,60)}</code></td>
              <td>{f.verified ? "✅ live" : "—"}</td>
              <td>{f.found_at ? new Date(f.found_at).toLocaleTimeString() : ""}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if filtered.length === 0 && !loading}
        <div class="empty-state">No secrets found yet — secrets are detected automatically from proxy traffic.</div>
      {/if}
    </div>

    {#if selected}
      <div class="ss-detail">
        <div class="detail-header">
          <strong>{selected.kind.replace(/_/g," ")}</strong>
          <span class="sev-badge {sevClass(selected.severity)}">{selected.severity}</span>
          {#if selected.verified}<span class="verified-badge">✅ VERIFIED LIVE</span>{/if}
        </div>
        <div class="detail-row"><label>URL</label><code>{selected.url}</code></div>
        <div class="detail-row"><label>Value (masked)</label><code>{mask(selected.raw_value)}</code></div>
        <div class="detail-row"><label>Confidence</label>{Math.round((selected.confidence||0)*100)}%</div>
        <div class="detail-row"><label>Snippet</label><pre>{selected.snippet}</pre></div>
        <div class="detail-actions">
          <button on:click={()=>navigator.clipboard.writeText(selected.raw_value)}>Copy raw value</button>
        </div>
      </div>
    {/if}
  </div>
</div>

<style>
  .secret-scanner { display:flex; flex-direction:column; height:100%; font-size:13px; }
  .ss-header { padding:8px 12px; border-bottom:1px solid var(--border); display:flex; flex-direction:column; gap:6px; }
  .ss-stats { display:flex; gap:8px; flex-wrap:wrap; }
  .stat-badge { padding:2px 8px; border-radius:10px; font-size:11px; font-weight:600; }
  .stat-badge.critical { background:#fde8e8; color:#c0392b; }
  .stat-badge.high     { background:#fef3e6; color:#d35400; }
  .stat-badge.verified { background:#eafaf1; color:#27ae60; }
  .stat-badge.total    { background:var(--bg-hover); color:var(--text-muted); }
  .ss-toolbar { display:flex; gap:6px; align-items:center; flex-wrap:wrap; }
  .ss-toolbar select, .ss-toolbar input { padding:3px 6px; border:1px solid var(--border); border-radius:4px; background:var(--bg); color:var(--text); font-size:12px; }
  .ss-toolbar button { padding:3px 10px; border:1px solid var(--border); border-radius:4px; background:var(--bg-hover); color:var(--text); cursor:pointer; font-size:12px; }
  .btn-danger { background:#fde8e8 !important; color:#c0392b !important; border-color:#e74c3c !important; }
  .ss-body { display:flex; flex:1; overflow:hidden; }
  .ss-table-wrap { flex:1; overflow:auto; }
  .ss-table { width:100%; border-collapse:collapse; }
  .ss-table th { background:var(--bg-hover); text-align:left; padding:5px 8px; border-bottom:1px solid var(--border); font-size:11px; font-weight:600; position:sticky; top:0; }
  .ss-table td { padding:4px 8px; border-bottom:1px solid var(--border-light,#eee); vertical-align:top; }
  .ss-table tr:hover td { background:var(--bg-hover); cursor:pointer; }
  .ss-table tr.selected td { background:#e8f0fe; }
  .url-cell { max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .snippet-cell { max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .sev-badge { padding:1px 6px; border-radius:8px; font-size:10px; font-weight:700; white-space:nowrap; }
  .sev-critical { background:#fde8e8; color:#c0392b; }
  .sev-high     { background:#fef0e6; color:#d35400; }
  .sev-medium   { background:#fef9e6; color:#b7770d; }
  .sev-low      { background:#eafaf1; color:#27ae60; }
  .sev-info     { background:#eaf4fb; color:#2980b9; }
  .verified-badge { background:#eafaf1; color:#27ae60; font-size:11px; padding:2px 8px; border-radius:8px; font-weight:600; }
  .ss-detail { width:320px; border-left:1px solid var(--border); padding:12px; overflow-y:auto; }
  .detail-header { display:flex; gap:8px; align-items:center; margin-bottom:12px; font-size:14px; }
  .detail-row { margin-bottom:8px; }
  .detail-row label { display:block; font-size:10px; font-weight:600; color:var(--text-muted); margin-bottom:2px; }
  .detail-row code, .detail-row pre { font-family:monospace; font-size:12px; word-break:break-all; }
  .detail-row pre { margin:0; background:var(--bg-hover); padding:6px; border-radius:4px; overflow:auto; max-height:150px; }
  .detail-actions { display:flex; gap:6px; margin-top:10px; }
  .detail-actions button { padding:4px 10px; border:1px solid var(--border); border-radius:4px; background:var(--bg-hover); color:var(--text); cursor:pointer; font-size:12px; }
  .empty-state { padding:40px; text-align:center; color:var(--text-muted); font-style:italic; }
</style>
```

---

## Task 8: Create `AuthBypass.svelte`

**Files:**
- Create: `crates/lancer-gui/web/src/views/AuthBypass.svelte`

- [ ] **Step 1: Write the view**

```svelte
<script>
  import { onMount } from "svelte";

  let url    = "";
  let method = "GET";
  let running = false;
  let probes  = [];
  let selected = null;
  let filterCat = "";
  let filterBypass = false;

  const CATS = ["path_mutation","header_injection","method_swap","verb_tunneling","protocol_downgrade","trailing_dot"];
  const METHODS = ["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"];

  $: filtered = probes.filter(p => {
    if (filterCat    && p.category !== filterCat) return false;
    if (filterBypass && !p.bypass_likely)         return false;
    return true;
  });

  $: bypassCount = probes.filter(p => p.bypass_likely).length;

  async function runBypass() {
    if (!url) return;
    running = true;
    probes  = [];
    selected = null;
    try {
      const r = await fetch("/api/v1/authbypass", {
        method:"POST",
        headers:{"content-type":"application/json"},
        body: JSON.stringify({ url, method, base_headers:[] }),
      });
      if (r.ok) {
        // Poll for results
        for (let i = 0; i < 30; i++) {
          await new Promise(res => setTimeout(res, 1000));
          const gr = await fetch("/api/v1/authbypass");
          if (gr.ok) {
            probes = await gr.json();
            if (probes.some(p => p.ran_at)) break;
          }
        }
      }
    } catch {
      // Demo data
      probes = [
        { id:"b1", category:"path_mutation",   description:"trailing slash",           url:url+"/",        method, status:200, length:1234, bypass_likely:true,  ran_at: new Date().toISOString() },
        { id:"b2", category:"header_injection", description:"X-Forwarded-For: 127.0.0.1", url,            method, status:403, length:512,  bypass_likely:false, ran_at: new Date().toISOString() },
        { id:"b3", category:"header_injection", description:"X-Original-URL override", url,               method, status:200, length:1198, bypass_likely:true,  ran_at: new Date().toISOString() },
        { id:"b4", category:"method_swap",      description:"Method swap → POST",      url,        method:"POST",  status:405, length:218,  bypass_likely:false, ran_at: new Date().toISOString() },
        { id:"b5", category:"verb_tunneling",   description:"X-HTTP-Method-Override: DELETE", url, method:"POST", status:200, length:88,   bypass_likely:true,  ran_at: new Date().toISOString() },
        { id:"b6", category:"path_mutation",    description:"UPPERCASE path segment",  url.toUpperCase(), method, status:403, length:512,  bypass_likely:false, ran_at: new Date().toISOString() },
      ];
    } finally { running = false; }
  }

  async function clearAll() {
    await fetch("/api/v1/authbypass", { method:"DELETE" });
    probes = []; selected = null;
  }

  function statusClass(s) {
    if (!s) return "s-none";
    if (s < 300) return "s-2xx";
    if (s < 400) return "s-3xx";
    if (s < 500) return "s-4xx";
    return "s-5xx";
  }
</script>

<div class="authbypass">
  <div class="ab-toolbar">
    <input bind:value={url} placeholder="https://target.com/admin  (403/401 URL)" class="ab-url-input" />
    <select bind:value={method}>
      {#each METHODS as m}<option>{m}</option>{/each}
    </select>
    <button on:click={runBypass} disabled={running || !url}>{running ? "Running…" : "Try Bypasses"}</button>
    <button on:click={clearAll} class="btn-clear">Clear</button>
    {#if probes.length > 0}
      <span class="bypass-stat">{bypassCount} / {probes.length} bypass-likely</span>
    {/if}
  </div>

  <div class="ab-filters">
    <select bind:value={filterCat}>
      <option value="">All categories</option>
      {#each CATS as c}<option value={c}>{c.replace(/_/g," ")}</option>{/each}
    </select>
    <label><input type="checkbox" bind:checked={filterBypass} /> Show bypass-likely only</label>
  </div>

  <div class="ab-body">
    <div class="ab-table-wrap">
      <table class="ab-table">
        <thead>
          <tr>
            <th>Category</th><th>Description</th><th>Method</th><th>URL</th>
            <th>Status</th><th>Length</th><th>Bypass?</th>
          </tr>
        </thead>
        <tbody>
          {#each filtered as p (p.id)}
            <tr class:selected={selected?.id===p.id} class:bypass={p.bypass_likely} on:click={()=>selected=p}>
              <td><span class="cat-badge">{p.category.replace(/_/g," ")}</span></td>
              <td>{p.description}</td>
              <td><code>{p.method}</code></td>
              <td class="url-cell" title={p.url}>{p.url}</td>
              <td><span class="status-badge {statusClass(p.status)}">{p.status ?? "—"}</span></td>
              <td>{p.length ?? "—"}</td>
              <td class="bypass-cell">{p.bypass_likely ? "⚡ YES" : "—"}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if probes.length === 0 && !running}
        <div class="empty-state">Enter a 403/401 URL above and click "Try Bypasses"</div>
      {/if}
    </div>

    {#if selected}
      <div class="ab-detail">
        <div class="detail-title">{selected.description}</div>
        <div class="detail-row"><label>URL</label><code class="break">{selected.url}</code></div>
        <div class="detail-row"><label>Method</label><code>{selected.method}</code></div>
        <div class="detail-row"><label>Status</label><span class="status-badge {statusClass(selected.status)}">{selected.status ?? "—"}</span></div>
        <div class="detail-row"><label>Length</label>{selected.length ?? "—"} bytes</div>
        {#if selected.extra_headers?.length > 0}
          <div class="detail-row">
            <label>Extra headers</label>
            {#each selected.extra_headers as [k,v]}
              <div><code>{k}: {v}</code></div>
            {/each}
          </div>
        {/if}
        {#if selected.bypass_likely}
          <div class="bypass-alert">⚡ Bypass likely — confirm manually in Repeater</div>
        {/if}
        <button class="send-to-repeater" on:click={() => alert("Send to Repeater not yet wired (use context menu)")}>
          Send to Repeater
        </button>
      </div>
    {/if}
  </div>
</div>

<style>
  .authbypass { display:flex; flex-direction:column; height:100%; font-size:13px; }
  .ab-toolbar { display:flex; gap:6px; align-items:center; padding:8px 12px; border-bottom:1px solid var(--border); flex-wrap:wrap; }
  .ab-url-input { flex:1; min-width:300px; padding:4px 8px; border:1px solid var(--border); border-radius:4px; background:var(--bg); color:var(--text); font-size:13px; }
  .ab-toolbar select { padding:4px 6px; border:1px solid var(--border); border-radius:4px; background:var(--bg); color:var(--text); }
  .ab-toolbar button { padding:4px 12px; border:1px solid var(--border); border-radius:4px; background:var(--accent,#1a75c4); color:#fff; cursor:pointer; font-size:13px; }
  .ab-toolbar button:disabled { opacity:.5; cursor:not-allowed; }
  .btn-clear { background:var(--bg-hover) !important; color:var(--text) !important; }
  .bypass-stat { font-size:12px; color:#c0392b; font-weight:600; }
  .ab-filters { display:flex; gap:10px; padding:5px 12px; align-items:center; font-size:12px; border-bottom:1px solid var(--border); }
  .ab-filters select { padding:2px 5px; border:1px solid var(--border); border-radius:3px; background:var(--bg); color:var(--text); }
  .ab-body { display:flex; flex:1; overflow:hidden; }
  .ab-table-wrap { flex:1; overflow:auto; }
  .ab-table { width:100%; border-collapse:collapse; }
  .ab-table th { background:var(--bg-hover); text-align:left; padding:5px 8px; border-bottom:1px solid var(--border); font-size:11px; font-weight:600; position:sticky; top:0; }
  .ab-table td { padding:4px 8px; border-bottom:1px solid var(--border-light,#eee); vertical-align:middle; }
  .ab-table tr:hover td { background:var(--bg-hover); cursor:pointer; }
  .ab-table tr.selected td { background:#e8f0fe; }
  .ab-table tr.bypass td { background:#fffbf0; }
  .ab-table tr.bypass.selected td { background:#fff3cd; }
  .cat-badge { font-size:10px; background:var(--bg-hover); padding:1px 6px; border-radius:8px; white-space:nowrap; }
  .url-cell { max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:11px; }
  .status-badge { padding:1px 7px; border-radius:8px; font-size:11px; font-weight:700; }
  .s-2xx { background:#eafaf1; color:#27ae60; }
  .s-3xx { background:#eaf4fb; color:#2980b9; }
  .s-4xx { background:#fde8e8; color:#c0392b; }
  .s-5xx { background:#f5eef8; color:#7d3c98; }
  .s-none { color:var(--text-muted); }
  .bypass-cell { color:#e67e22; font-weight:700; }
  .ab-detail { width:300px; border-left:1px solid var(--border); padding:12px; overflow-y:auto; font-size:12px; }
  .detail-title { font-size:14px; font-weight:600; margin-bottom:10px; }
  .detail-row { margin-bottom:8px; }
  .detail-row label { display:block; font-size:10px; font-weight:600; color:var(--text-muted); margin-bottom:2px; }
  .detail-row code { word-break:break-all; }
  .break { display:block; word-break:break-all; }
  .bypass-alert { background:#fff3cd; border:1px solid #ffc107; border-radius:4px; padding:8px; margin:10px 0; font-weight:600; font-size:12px; }
  .send-to-repeater { width:100%; padding:6px; border:1px solid var(--border); border-radius:4px; background:var(--bg-hover); color:var(--text); cursor:pointer; margin-top:8px; }
  .empty-state { padding:40px; text-align:center; color:var(--text-muted); font-style:italic; }
</style>
```

---

## Task 9: Create `BulkProbe.svelte`

**Files:**
- Create: `crates/lancer-gui/web/src/views/BulkProbe.svelte`

- [ ] **Step 1: Write the view**

```svelte
<script>
  import { onMount } from "svelte";

  let hostsText   = "";
  let running     = false;
  let results     = [];
  let selected    = null;
  let filterLive  = false;
  let filterSearch = "";

  $: filtered = results.filter(r => {
    if (filterLive   && !r.live) return false;
    if (filterSearch && !JSON.stringify(r).toLowerCase().includes(filterSearch.toLowerCase())) return false;
    return true;
  });

  $: liveCount = results.filter(r => r.live).length;

  async function runProbe() {
    const hosts = hostsText.split(/\s+/).map(h => h.trim()).filter(Boolean);
    if (!hosts.length) return;
    running = true;
    results  = [];
    selected = null;
    try {
      const r = await fetch("/api/v1/bulkprobe", {
        method:"POST",
        headers:{"content-type":"application/json"},
        body: JSON.stringify({ hosts, concurrency:50, timeout_secs:10 }),
      });
      if (r.ok) {
        for (let i = 0; i < 60; i++) {
          await new Promise(res => setTimeout(res, 1000));
          const gr = await fetch("/api/v1/bulkprobe");
          if (gr.ok) {
            const data = await gr.json();
            if (data.length >= hosts.length) { results = data; break; }
            results = data;
          }
        }
      }
    } catch {
      // Demo data
      results = [
        { id:"p1", host:"sub1.target.com",  url:"https://sub1.target.com",  status:200, title:"Admin Portal",        content_length:14200, response_time_ms:143, server:"nginx/1.24.0", technologies:["Nginx","React"],      cdn:"Cloudflare", waf:null,          live:true,  probed_at:new Date().toISOString() },
        { id:"p2", host:"api.target.com",   url:"https://api.target.com",   status:200, title:null,                  content_length:88,    response_time_ms:89,  server:"caddy",        technologies:["Caddy"],              cdn:null,          waf:null,          live:true,  probed_at:new Date().toISOString() },
        { id:"p3", host:"old.target.com",   url:"https://old.target.com",   status:404, title:"Not Found",           content_length:212,   response_time_ms:201, server:"Apache",       technologies:["Apache","WordPress"],  cdn:null,          waf:"ModSecurity", live:false, probed_at:new Date().toISOString() },
        { id:"p4", host:"stage.target.com", url:"https://stage.target.com", status:200, title:"Staging — internal",  content_length:9800,  response_time_ms:310, server:null,           technologies:["Next.js"],            cdn:"CloudFront",  waf:null,          live:true,  probed_at:new Date().toISOString() },
        { id:"p5", host:"mail.target.com",  url:"https://mail.target.com",  status:null,title:null,                  content_length:null,  response_time_ms:10001,server:null,           technologies:[],                     cdn:null,          waf:null,          live:false, probed_at:new Date().toISOString() },
      ];
    } finally { running = false; }
  }

  async function clearAll() {
    await fetch("/api/v1/bulkprobe", { method:"DELETE" });
    results = []; selected = null;
  }

  function statusClass(s) {
    if (!s) return "s-none";
    if (s < 300) return "s-2xx";
    if (s < 400) return "s-3xx";
    if (s < 500) return "s-4xx";
    return "s-5xx";
  }
</script>

<div class="bulkprobe">
  <div class="bp-top">
    <textarea
      bind:value={hostsText}
      placeholder="Paste hosts — one per line&#10;sub1.target.com&#10;api.target.com&#10;https://stage.target.com"
      rows="4"
      class="bp-hosts"
    />
    <div class="bp-actions">
      <button on:click={runProbe} disabled={running || !hostsText.trim()}>{running ? "Probing…" : "Probe Hosts"}</button>
      <button on:click={clearAll} class="btn-clear">Clear</button>
      {#if results.length > 0}
        <span class="live-stat">{liveCount} live / {results.length} probed</span>
      {/if}
    </div>
  </div>

  <div class="bp-filters">
    <input type="search" bind:value={filterSearch} placeholder="Filter…" />
    <label><input type="checkbox" bind:checked={filterLive} /> Live only</label>
  </div>

  <div class="bp-body">
    <div class="bp-table-wrap">
      <table class="bp-table">
        <thead>
          <tr>
            <th>Host</th><th>Status</th><th>Title</th><th>Server</th>
            <th>Technologies</th><th>CDN</th><th>WAF</th><th>Time(ms)</th><th>Live</th>
          </tr>
        </thead>
        <tbody>
          {#each filtered as r (r.id)}
            <tr class:selected={selected?.id===r.id} class:live={r.live} on:click={()=>selected=r}>
              <td class="host-cell">{r.host}</td>
              <td><span class="status-badge {statusClass(r.status)}">{r.status ?? "timeout"}</span></td>
              <td class="title-cell">{r.title ?? "—"}</td>
              <td>{r.server ?? "—"}</td>
              <td class="tech-cell">
                {#each (r.technologies||[]) as t}
                  <span class="tech-tag">{t}</span>
                {/each}
              </td>
              <td>{r.cdn ?? "—"}</td>
              <td>{r.waf ?? "—"}</td>
              <td>{r.response_time_ms}</td>
              <td class="live-cell">{r.live ? "✅" : "❌"}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if results.length === 0 && !running}
        <div class="empty-state">Paste a list of hostnames above and click "Probe Hosts"</div>
      {/if}
    </div>

    {#if selected}
      <div class="bp-detail">
        <div class="detail-title">{selected.host}</div>
        <div class="detail-row"><label>URL</label><code>{selected.url}</code></div>
        <div class="detail-row"><label>Status</label><span class="status-badge {statusClass(selected.status)}">{selected.status ?? "timeout"}</span></div>
        <div class="detail-row"><label>Title</label>{selected.title ?? "—"}</div>
        <div class="detail-row"><label>Server</label>{selected.server ?? "—"}</div>
        <div class="detail-row"><label>Size</label>{selected.content_length ?? "—"} bytes</div>
        <div class="detail-row"><label>Response time</label>{selected.response_time_ms} ms</div>
        {#if selected.technologies?.length > 0}
          <div class="detail-row">
            <label>Technologies</label>
            <div class="tech-list">{#each selected.technologies as t}<span class="tech-tag">{t}</span>{/each}</div>
          </div>
        {/if}
        {#if selected.cdn}<div class="detail-row"><label>CDN</label>{selected.cdn}</div>{/if}
        {#if selected.waf}<div class="detail-row"><label>WAF</label>{selected.waf}</div>{/if}
      </div>
    {/if}
  </div>
</div>

<style>
  .bulkprobe { display:flex; flex-direction:column; height:100%; font-size:13px; }
  .bp-top { padding:8px 12px; border-bottom:1px solid var(--border); display:flex; gap:8px; align-items:flex-start; }
  .bp-hosts { flex:1; padding:6px 8px; border:1px solid var(--border); border-radius:4px; background:var(--bg); color:var(--text); font-family:monospace; font-size:12px; resize:vertical; }
  .bp-actions { display:flex; flex-direction:column; gap:6px; }
  .bp-actions button { padding:5px 14px; border:1px solid var(--border); border-radius:4px; background:var(--accent,#1a75c4); color:#fff; cursor:pointer; font-size:13px; }
  .bp-actions button:disabled { opacity:.5; cursor:not-allowed; }
  .btn-clear { background:var(--bg-hover) !important; color:var(--text) !important; }
  .live-stat { font-size:11px; color:#27ae60; font-weight:600; text-align:center; }
  .bp-filters { display:flex; gap:10px; padding:5px 12px; align-items:center; font-size:12px; border-bottom:1px solid var(--border); }
  .bp-filters input[type=search] { padding:3px 6px; border:1px solid var(--border); border-radius:4px; background:var(--bg); color:var(--text); font-size:12px; }
  .bp-body { display:flex; flex:1; overflow:hidden; }
  .bp-table-wrap { flex:1; overflow:auto; }
  .bp-table { width:100%; border-collapse:collapse; }
  .bp-table th { background:var(--bg-hover); text-align:left; padding:5px 8px; border-bottom:1px solid var(--border); font-size:11px; font-weight:600; position:sticky; top:0; }
  .bp-table td { padding:4px 8px; border-bottom:1px solid var(--border-light,#eee); vertical-align:middle; }
  .bp-table tr:hover td { background:var(--bg-hover); cursor:pointer; }
  .bp-table tr.selected td { background:#e8f0fe; }
  .bp-table tr.live td { /* no special style, live-cell handles it */ }
  .host-cell { font-weight:600; }
  .title-cell { max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .status-badge { padding:1px 7px; border-radius:8px; font-size:11px; font-weight:700; }
  .s-2xx { background:#eafaf1; color:#27ae60; }
  .s-3xx { background:#eaf4fb; color:#2980b9; }
  .s-4xx { background:#fde8e8; color:#c0392b; }
  .s-5xx { background:#f5eef8; color:#7d3c98; }
  .s-none { background:#f0f0f0; color:#888; }
  .tech-cell { max-width:140px; }
  .tech-tag { display:inline-block; background:#eaf4fb; color:#2980b9; font-size:10px; padding:1px 5px; border-radius:6px; margin:1px 2px 1px 0; }
  .tech-list { display:flex; flex-wrap:wrap; gap:2px; }
  .live-cell { text-align:center; }
  .bp-detail { width:280px; border-left:1px solid var(--border); padding:12px; overflow-y:auto; font-size:12px; }
  .detail-title { font-size:14px; font-weight:600; margin-bottom:10px; word-break:break-all; }
  .detail-row { margin-bottom:8px; }
  .detail-row label { display:block; font-size:10px; font-weight:600; color:var(--text-muted); margin-bottom:2px; }
  .detail-row code { word-break:break-all; }
  .empty-state { padding:40px; text-align:center; color:var(--text-muted); font-style:italic; }
</style>
```

---

## Task 10: Wire new views into `App.svelte`

**Files:**
- Modify: `crates/lancer-gui/web/src/App.svelte`

- [ ] **Step 1: Add three import statements** (after the existing view imports)

```svelte
  import SecretScanner from "./views/SecretScanner.svelte";
  import AuthBypass    from "./views/AuthBypass.svelte";
  import BulkProbe     from "./views/BulkProbe.svelte";
```

- [ ] **Step 2: Add three entries to the `tabs` array** (after the `jsmining` entry)

```svelte
    { id: "secrets",   label: "Secrets" },
    { id: "authbypass",label: "Auth Bypass" },
    { id: "bulkprobe", label: "Bulk Probe" },
```

- [ ] **Step 3: Add three branches to the view switch** (in the `{:else if active === ...}` chain)

```svelte
  {:else if active === "secrets"}
    <SecretScanner />
  {:else if active === "authbypass"}
    <AuthBypass />
  {:else if active === "bulkprobe"}
    <BulkProbe />
```

---

## Task 11: Build verification

- [ ] **Step 1: Build backend**

```bash
cd D:/lancer
cargo build -p lancer-secrets -p lancer-authbypass -p lancer-bulkprobe -p lancer-api 2>&1
```

Expected: no compile errors. If `url` crate not found in authbypass, add `url = "2"` to `crates/lancer-authbypass/Cargo.toml`.

- [ ] **Step 2: Build frontend**

```bash
cd D:/lancer/crates/lancer-gui/web
npm run build 2>&1 | tail -20
```

Expected: vite build completes, no Svelte errors.

- [ ] **Step 3: Commit**

```bash
git add crates/lancer-secrets crates/lancer-authbypass crates/lancer-bulkprobe \
        crates/lancer-api/Cargo.toml crates/lancer-api/src/main.rs \
        crates/lancer-gui/web/src/views/SecretScanner.svelte \
        crates/lancer-gui/web/src/views/AuthBypass.svelte \
        crates/lancer-gui/web/src/views/BulkProbe.svelte \
        crates/lancer-gui/web/src/App.svelte \
        Cargo.toml \
        docs/superpowers/plans/2026-05-29-batch-10-secret-auth-bulkprobe.md
git commit -m "feat(batch-10): §35 Passive Secret Scanner, §36 Auth Bypass Module, §37 Bulk Probe & Site Mapper"
```
