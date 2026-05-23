//! Stateful BFS crawler.
//!
//! Pulls the entry URL, extracts anchor hrefs and script src URLs, queues
//! every in-scope URL it finds, and shovels each `(request, response)` pair
//! through the supplied callback.
//!
//! This is the Phase-1 crawler — no JS rendering, no form auto-submission.
//! A Chromium-driven crawler can plug in via the same `CrawlSink` interface.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
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
                sink2.observed(&req, &resp).await;
                let body = resp.body_text().unwrap_or("").to_string();
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
                Some(found)
            });
            count += 1;
            let next = handle.await.ok().flatten().unwrap_or_default();
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
