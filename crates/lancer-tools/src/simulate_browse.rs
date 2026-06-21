//! Simulate manual testing — human-like browse over a target.
//!
//! Walks the site map / a wordlist of paths with random delays and a small
//! set of "human-like" actions (vary User-Agent, follow ~30% of seen links,
//! occasionally re-fetch the same page). Doesn't run JS — that needs Chromium.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use lancer_core::scope::Scope;
use lancer_core::sitemap::SiteMap;
use lancer_core::HttpRequest;
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::client::HttpClient;
use crate::engagement::find_anchors;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowseConfig {
    pub max_pages: usize,
    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
    pub revisit_chance: f32,
    pub follow_chance: f32,
}

impl Default for BrowseConfig {
    fn default() -> Self {
        Self {
            max_pages: 75,
            min_delay_ms: 300,
            max_delay_ms: 2500,
            revisit_chance: 0.10,
            follow_chance: 0.30,
        }
    }
}

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148",
];

pub async fn simulate(
    client: HttpClient,
    entry: &str,
    scope: Arc<RwLock<Scope>>,
    sitemap: Arc<RwLock<SiteMap>>,
    config: BrowseConfig,
) -> Result<usize> {
    let mut visited: Vec<String> = Vec::new();
    let mut to_visit: Vec<String> = vec![entry.to_string()];
    let mut count = 0;

    while let Some(url) = to_visit.pop() {
        if count >= config.max_pages {
            break;
        }
        let Ok(mut req) = HttpRequest::builder("GET", &url) else { continue };
        if !scope.read().is_in_scope(&req) {
            continue;
        }
        {
            let mut rng = rand::thread_rng();
            let ua = USER_AGENTS.choose(&mut rng).copied().unwrap_or(USER_AGENTS[0]);
            req.set_header("User-Agent", ua);
            req.set_header("Accept", "text/html,application/xhtml+xml,*/*;q=0.8");
        }
        let delay = {
            let mut rng = rand::thread_rng();
            let lo = config.min_delay_ms.min(config.max_delay_ms);
            let hi = config.min_delay_ms.max(config.max_delay_ms);
            rng.gen_range(lo..=hi)
        };
        tokio::time::sleep(Duration::from_millis(delay)).await;

        let Ok(resp) = client.send(&req).await else { continue };
        sitemap.write().record_pair(&req, &resp);
        visited.push(url.clone());
        count += 1;

        if let Some(body) = resp.body_text() {
            let mut anchors = find_anchors(body, &url);
            anchors.retain(|a| {
                HttpRequest::builder("GET", a)
                    .map(|r| scope.read().is_in_scope(&r))
                    .unwrap_or(false)
            });
            let mut rng = rand::thread_rng();
            for a in anchors {
                if rng.gen::<f32>() < config.follow_chance && !visited.contains(&a) {
                    to_visit.push(a);
                }
            }
            if !visited.is_empty() && rng.gen::<f32>() < config.revisit_chance {
                let pick = visited.choose(&mut rng).cloned();
                if let Some(p) = pick {
                    to_visit.push(p);
                }
            }
        }
    }
    Ok(count)
}
