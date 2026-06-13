//! §4.6 Mass Fuzz — high-speed async content/parameter fuzzer (ffuf equivalent).
//!
//! Substitutes the `FUZZ` marker in a URL template with every word (× optional
//! extensions), fires them concurrently through the shared HTTP client, and
//! returns per-request status / size / word / line counts. Match and filter
//! sets (ffuf's `-mc` / `-fc` / `-fs`) prune the result set server-side.

use std::sync::Arc;
use std::time::Instant;

use lancer_core::HttpRequest;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::client::HttpClient;

/// A small built-in directory/file wordlist so the feature works with no
/// external SecLists download. The GUI can also paste a custom list.
pub const COMMON_WORDLIST: &[&str] = &[
    "admin", "administrator", "login", "logout", "register", "signup", "signin",
    "api", "api/v1", "api/v2", "graphql", "swagger", "swagger-ui", "openapi.json",
    "config", "config.json", ".env", ".git", ".git/config", ".gitignore", ".svn",
    "backup", "backups", "bak", "old", "test", "tests", "dev", "staging", "tmp",
    "uploads", "upload", "files", "file", "download", "downloads", "assets",
    "static", "public", "private", "internal", "secret", "secrets", "hidden",
    "dashboard", "panel", "cpanel", "phpmyadmin", "wp-admin", "wp-login.php",
    "wp-config.php", "wp-content", "wp-json", "user", "users", "account", "accounts",
    "settings", "setup", "install", "installer", "console", "debug", "status",
    "health", "healthz", "metrics", "actuator", "actuator/health", "info", "version",
    "robots.txt", "sitemap.xml", "crossdomain.xml", ".htaccess", ".htpasswd",
    "server-status", "server-info", "web.config", "appsettings.json", "package.json",
    "composer.json", "Dockerfile", "docker-compose.yml", "id_rsa", "credentials",
    "token", "tokens", "auth", "oauth", "sso", "jwt", "session", "logs", "log",
];

#[derive(Debug, Clone, Deserialize)]
pub struct MassFuzzConfig {
    /// URL template containing the literal marker `FUZZ`.
    pub url: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub words: Vec<String>,
    /// Extensions appended to each word, e.g. `["", ".php", ".bak"]`.
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub concurrency: Option<usize>,
    /// Only keep responses with these statuses (empty = keep all).
    #[serde(default)]
    pub match_status: Vec<u16>,
    /// Drop responses with these statuses.
    #[serde(default)]
    pub filter_status: Vec<u16>,
    /// Drop responses with these exact byte sizes (calibration / noise removal).
    #[serde(default)]
    pub filter_size: Vec<usize>,
    #[serde(default)]
    pub max_requests: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MassFuzzResult {
    pub word: String,
    pub url: String,
    pub status: u16,
    pub length: usize,
    pub words: usize,
    pub lines: usize,
    pub time_ms: u64,
}

/// Hard cap so a careless wordlist × extension product can't run forever.
const HARD_CAP: usize = 50_000;

pub async fn run(cfg: MassFuzzConfig, client: HttpClient) -> Vec<MassFuzzResult> {
    let method = cfg.method.clone().unwrap_or_else(|| "GET".into());
    let concurrency = cfg.concurrency.unwrap_or(40).clamp(1, 256);
    let sem = Arc::new(Semaphore::new(concurrency));
    let cap = cfg.max_requests.unwrap_or(HARD_CAP).min(HARD_CAP);

    let exts = if cfg.extensions.is_empty() { vec![String::new()] } else { cfg.extensions.clone() };
    let mut work: Vec<(String, String)> = Vec::new();
    'outer: for w in &cfg.words {
        let w = w.trim();
        if w.is_empty() { continue; }
        for e in &exts {
            let token = format!("{w}{e}");
            let url = cfg.url.replace("FUZZ", &token);
            work.push((token, url));
            if work.len() >= cap { break 'outer; }
        }
    }

    let mut handles = Vec::with_capacity(work.len());
    for (word, url) in work {
        let Ok(permit) = sem.clone().acquire_owned().await else { break };
        let client = client.clone();
        let method = method.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let start = Instant::now();
            let req = HttpRequest::builder(method.as_str(), &url).ok()?;
            let resp = client.send(&req).await.ok()?;
            let elapsed = start.elapsed().as_millis() as u64;
            let body = resp.body_text().unwrap_or("");
            Some(MassFuzzResult {
                word,
                url,
                status: resp.status,
                length: resp.body.len(),
                words: body.split_whitespace().count(),
                lines: body.lines().count(),
                time_ms: elapsed,
            })
        }));
    }

    let mut out = Vec::new();
    for h in handles {
        let Ok(Some(r)) = h.await else { continue };
        if !cfg.match_status.is_empty() && !cfg.match_status.contains(&r.status) { continue; }
        if cfg.filter_status.contains(&r.status) { continue; }
        if cfg.filter_size.contains(&r.length) { continue; }
        out.push(r);
    }
    out.sort_by(|a, b| a.word.cmp(&b.word));
    out
}
