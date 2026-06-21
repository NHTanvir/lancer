//! §37 Bulk Probe & Site Mapper — concurrent HTTP prober for host lists.
//!
//! Accepts a list of hostnames/URLs, probes each concurrently, returns rich
//! per-host metadata: status, title, server, technologies, CDN, WAF.

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Types ─────────────────────────────────────────────────────────────────────

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
    pub cdn: Option<String>,
    pub waf: Option<String>,
    pub live: bool,
    pub probed_at: chrono::DateTime<chrono::Utc>,
}

// ── Detection helpers ─────────────────────────────────────────────────────────

fn detect_technologies(headers: &reqwest::header::HeaderMap, body: &str) -> Vec<String> {
    let mut techs = Vec::new();
    if let Some(s) = headers.get("server").and_then(|v| v.to_str().ok()) {
        let sl = s.to_lowercase();
        if sl.contains("nginx")      { techs.push("Nginx".into()); }
        if sl.contains("apache")     { techs.push("Apache".into()); }
        if sl.contains("iis")        { techs.push("IIS".into()); }
        if sl.contains("caddy")      { techs.push("Caddy".into()); }
        if sl.contains("gunicorn")   { techs.push("Gunicorn".into()); }
        if sl.contains("cloudflare") { techs.push("Cloudflare".into()); }
    }
    if let Some(v) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
        let vl = v.to_lowercase();
        if vl.contains("php")        { techs.push("PHP".into()); }
        else if vl.contains("asp")   { techs.push("ASP.NET".into()); }
        else if vl.contains("express") { techs.push("Express".into()); }
        else                          { techs.push(format!("X-Powered-By:{v}")); }
    }
    if headers.get("x-generator").is_some() {
        if let Some(v) = headers.get("x-generator").and_then(|v| v.to_str().ok()) {
            techs.push(format!("Generator:{v}"));
        }
    }
    // Body heuristics
    if body.contains("wp-content") || body.contains("wp-includes") {
        techs.push("WordPress".into());
    }
    if body.contains("Drupal.settings") || body.contains("/sites/default/") {
        techs.push("Drupal".into());
    }
    if body.contains("Joomla!") || body.contains("/components/com_") {
        techs.push("Joomla".into());
    }
    if body.contains("__NEXT_DATA__")         { techs.push("Next.js".into()); }
    if body.contains("nuxt-app") || body.contains("__NUXT_")
                                               { techs.push("Nuxt.js".into()); }
    if body.contains("ng-version")             { techs.push("Angular".into()); }
    if body.contains("React.createElement")   { techs.push("React".into()); }
    if body.contains("data-svelte-h") || body.contains("sveltekit") {
        techs.push("SvelteKit".into());
    }
    if body.contains("laravel_token") || body.contains("Laravel") {
        techs.push("Laravel".into());
    }
    if body.contains("django") || body.contains("csrfmiddlewaretoken") {
        techs.push("Django".into());
    }
    techs.dedup();
    techs
}

fn detect_cdn(headers: &reqwest::header::HeaderMap) -> Option<String> {
    if headers.get("cf-ray").is_some() || headers.get("cf-cache-status").is_some() {
        return Some("Cloudflare".into());
    }
    if headers.get("x-amz-cf-id").is_some() || headers.get("x-amz-cf-pop").is_some() {
        return Some("CloudFront".into());
    }
    if headers.get("x-akamai-transformed").is_some()
        || headers.get("x-check-cacheable").is_some()
    {
        return Some("Akamai".into());
    }
    if headers.get("x-fastly-request-id").is_some() {
        return Some("Fastly".into());
    }
    if headers.get("x-cache").and_then(|v| v.to_str().ok()).map_or(false, |v| v.contains("Varnish")) {
        return Some("Varnish".into());
    }
    None
}

fn detect_waf(headers: &reqwest::header::HeaderMap, body: &str) -> Option<String> {
    if headers.get("x-sucuri-id").is_some()    { return Some("Sucuri".into()); }
    if headers.get("x-fw-hash").is_some()      { return Some("Wordfence".into()); }
    if body.contains("Request blocked by ModSecurity") { return Some("ModSecurity".into()); }
    if body.contains("The requested URL was rejected") { return Some("F5 ASM".into()); }
    if body.contains("Access denied | ")       { return Some("Barracuda".into()); }
    None
}

fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    let start = lower.find("<title>")? + 7;
    let end = start + lower[start..].find("</title>")?;
    // `start`/`end` are valid char boundaries within `lower`; slice `lower`, not
    // `body`, because `to_lowercase()` is not length-preserving and offsets
    // computed on `lower` may not be char boundaries in `body`.
    Some(lower[start..end].trim().chars().take(120).collect())
}

// ── Single host probe ─────────────────────────────────────────────────────────

async fn probe_one(host: String, timeout_secs: u64) -> ProbeResult {
    let url = if host.starts_with("http://") || host.starts_with("https://") {
        host.clone()
    } else {
        format!("https://{host}")
    };

    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            return ProbeResult {
                id: Uuid::new_v4(),
                host,
                url,
                status: None,
                title: None,
                content_length: None,
                response_time_ms: 0,
                server: None,
                technologies: vec![],
                cdn: None,
                waf: None,
                live: false,
                probed_at: chrono::Utc::now(),
            };
        }
    };

    let start = std::time::Instant::now();
    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            let cdn = detect_cdn(&headers);
            let server = headers
                .get("server")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let content_length = resp.content_length();
            let body = resp.text().await.unwrap_or_default();
            let elapsed = start.elapsed().as_millis() as u64;
            let title = extract_title(&body);
            let technologies = detect_technologies(&headers, &body);
            let waf = detect_waf(&headers, &body);
            ProbeResult {
                id: Uuid::new_v4(),
                host,
                url,
                status: Some(status),
                title,
                content_length,
                response_time_ms: elapsed,
                server,
                technologies,
                cdn,
                waf,
                live: status < 500,
                probed_at: chrono::Utc::now(),
            }
        }
        Err(_) => ProbeResult {
            id: Uuid::new_v4(),
            host,
            url,
            status: None,
            title: None,
            content_length: None,
            response_time_ms: start.elapsed().as_millis() as u64,
            server: None,
            technologies: vec![],
            cdn: None,
            waf: None,
            live: false,
            probed_at: chrono::Utc::now(),
        },
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Probe all hosts concurrently, up to `req.concurrency` at a time.
pub async fn run_probes(req: ProbeRequest) -> Vec<ProbeResult> {
    let concurrency = req.concurrency.max(1);
    let timeout = req.timeout_secs;
    futures::stream::iter(req.hosts)
        .map(move |h| probe_one(h, timeout))
        .buffer_unordered(concurrency)
        .collect()
        .await
}
