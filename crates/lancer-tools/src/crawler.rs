//! Stateful BFS crawler.
//!
//! Pulls the entry URL, extracts anchor hrefs and script src URLs, queues
//! every in-scope URL it finds, and shovels each `(request, response)` pair
//! through the supplied callback.
//!
//! This is the Phase-1 crawler — no JS rendering, no form auto-submission.
//! A Chromium-driven crawler can plug in via the same `CrawlSink` interface.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sha2::{Digest as _, Sha256};
use async_trait::async_trait;
use lancer_core::scope::Scope;
use lancer_core::sitemap::{NodeKind, SiteMap};
use lancer_core::{HttpRequest, HttpResponse};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::client::HttpClient;
use crate::engagement::{find_anchors, find_scripts};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlConfig {
    pub max_depth: usize,
    pub max_pages: usize,
    pub concurrency: usize,
    pub throttle_ms: u64,
    pub include_scripts: bool,
    pub follow_subdomains: bool,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            max_depth: 4,
            max_pages: 250,
            concurrency: 8,
            throttle_ms: 0,
            include_scripts: false,
            follow_subdomains: false,
        }
    }
}

#[async_trait]
pub trait CrawlSink: Send + Sync {
    async fn observed(&self, request: &HttpRequest, response: &HttpResponse);
}

#[async_trait]
impl CrawlSink for parking_lot::RwLock<SiteMap> {
    async fn observed(&self, request: &HttpRequest, response: &HttpResponse) {
        self.write().record_pair(request, response);
    }
}

pub struct Crawler {
    pub client: HttpClient,
    pub config: CrawlConfig,
    pub scope: Arc<RwLock<Scope>>,
}

impl Crawler {
    pub fn new(client: HttpClient, config: CrawlConfig, scope: Arc<RwLock<Scope>>) -> Self {
        Self { client, config, scope }
    }

    /// Crawl starting from `entry_url`. Returns the number of pages fetched.
    pub async fn run<S: CrawlSink + 'static>(
        &self,
        entry_url: &str,
        sink: Arc<S>,
    ) -> Result<usize> {
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();
        let mut seen: HashSet<String> = HashSet::new();
        // Location fingerprints (response-shape hashes) keyed by their first
        // canonical URL. Subsequent URLs whose response hashes the same way
        // are recorded but not re-crawled.
        let mut fingerprints: HashMap<String, String> = HashMap::new();
        queue.push_back((entry_url.to_string(), 0));
        seen.insert(entry_url.to_string());

        let sem = Arc::new(Semaphore::new(self.config.concurrency.max(1)));
        let mut count = 0usize;

        while let Some((url, depth)) = queue.pop_front() {
            if count >= self.config.max_pages {
                break;
            }
            let req = match HttpRequest::builder("GET", &url) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if !self.scope.read().is_in_scope(&req) {
                continue;
            }

            let permit = sem.clone().acquire_owned().await?;
            let client = self.client.clone();
            let throttle = self.config.throttle_ms;
            let url_clone = url.clone();
            let entry_host = url::Url::parse(entry_url)
                .ok()
                .and_then(|u| u.host_str().map(|s| s.to_string()));
            let follow_subs = self.config.follow_subdomains;
            let include_scripts = self.config.include_scripts;
            let sink2 = sink.clone();
            let handle = tokio::spawn(async move {
                let _permit = permit;
                if throttle > 0 {
                    tokio::time::sleep(Duration::from_millis(throttle)).await;
                }
                let resp = client.send(&req).await.ok()?;
                let body = resp.body_text().unwrap_or("").to_string();
                let fingerprint = location_fingerprint(&body, resp.status);
                sink2.observed(&req, &resp).await;
                let mut found = Vec::new();
                for href in find_anchors(&body, &url_clone) {
                    if same_host(&href, entry_host.as_deref(), follow_subs) {
                        found.push(href);
                    }
                }
                if include_scripts {
                    for src in find_scripts(&body, &url_clone) {
                        if same_host(&src, entry_host.as_deref(), follow_subs) {
                            found.push(src);
                        }
                    }
                }
                Some((found, fingerprint))
            });
            count += 1;
            let (next, fingerprint) = match handle.await.ok().flatten() {
                Some(x) => x,
                None => continue,
            };
            // Skip queuing children if we've already seen the same response
            // shape under a different URL — this is the "Location
            // fingerprinting" item from plan.md §5.1.
            if let Some(prev) = fingerprints.get(&fingerprint) {
                tracing::debug!(this = %url, mirrors = %prev, "skipping; same location fingerprint");
                continue;
            } else {
                fingerprints.insert(fingerprint, url.clone());
            }
            if depth + 1 > self.config.max_depth {
                continue;
            }
            for n in next {
                if seen.insert(n.clone()) {
                    queue.push_back((n, depth + 1));
                }
            }
        }
        Ok(count)
    }
}

/// Canonicalise a response body to a stable fingerprint so two URLs that
/// render the "same page" don't both get crawled. We strip whitespace and
/// digit runs (so per-render IDs / CSRF tokens don't change the hash), then
/// SHA-256.
fn location_fingerprint(body: &str, status: u16) -> String {
    let mut buf = String::with_capacity(body.len());
    buf.push_str(&format!("{status}|"));
    let mut last_was_digit = false;
    for c in body.chars() {
        if c.is_whitespace() {
            continue;
        }
        if c.is_ascii_digit() {
            if !last_was_digit {
                buf.push('#');
                last_was_digit = true;
            }
            continue;
        }
        last_was_digit = false;
        buf.push(c);
    }
    let mut hasher = Sha256::new();
    hasher.update(buf.as_bytes());
    hex::encode(hasher.finalize())
}

fn same_host(candidate: &str, entry: Option<&str>, follow_subdomains: bool) -> bool {
    let Ok(u) = url::Url::parse(candidate) else {
        return false;
    };
    let Some(host) = u.host_str() else { return false };
    match entry {
        None => true,
        Some(e) => {
            if host == e {
                true
            } else if follow_subdomains {
                host.ends_with(&format!(".{e}"))
            } else {
                false
            }
        }
    }
}
