//! §45 Shodan Host Enrichment — REST API client.
//!
//! Wraps the Shodan REST API + free InternetDB fallback. Caches results for
//! 24h so a re-open of a Site Map node doesn't burn API quota.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub ip: String,
    pub hostnames: Vec<String>,
    pub ports: Vec<u16>,
    pub vulns: Vec<String>,
    pub os: Option<String>,
    pub tags: Vec<String>,
    pub last_update: Option<String>,
    pub org: Option<String>,
    pub country: Option<String>,
    pub source: HostSource,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostSource { Shodan, InternetDb, Cache }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveInfo {
    pub cve: String,
    pub summary: Option<String>,
    pub cvss: Option<f64>,
    pub cvss_v3: Option<f64>,
    pub epss: Option<f64>,
    pub kev: bool,
    pub references: Vec<String>,
}

#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    cached_at: std::time::Instant,
}

const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

#[derive(Debug, Clone)]
pub struct ShodanClient {
    api_key: Option<String>,
    host_cache: Arc<RwLock<HashMap<String, CacheEntry<HostInfo>>>>,
    cve_cache: Arc<RwLock<HashMap<String, CacheEntry<CveInfo>>>>,
}

impl ShodanClient {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            api_key,
            host_cache: Arc::new(RwLock::new(HashMap::new())),
            cve_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn from_env() -> Self {
        Self::new(std::env::var("SHODAN_API_KEY").ok())
    }

    pub async fn host(&self, ip: &str) -> Option<HostInfo> {
        // Cache first
        if let Some(entry) = self.host_cache.read().get(ip) {
            if entry.cached_at.elapsed() < CACHE_TTL {
                let mut v = entry.value.clone();
                v.source = HostSource::Cache;
                return Some(v);
            }
        }

        let mut info = if let Some(k) = &self.api_key {
            self.fetch_shodan_host(ip, k).await
        } else {
            None
        };
        if info.is_none() {
            info = self.fetch_internetdb(ip).await;
        }
        if let Some(i) = &info {
            self.host_cache.write().insert(
                ip.to_string(),
                CacheEntry { value: i.clone(), cached_at: std::time::Instant::now() },
            );
        }
        info
    }

    pub async fn cve(&self, cve_id: &str) -> Option<CveInfo> {
        if let Some(entry) = self.cve_cache.read().get(cve_id) {
            if entry.cached_at.elapsed() < CACHE_TTL {
                return Some(entry.value.clone());
            }
        }
        // Shodan CVE endpoint
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .ok()?;
        let url = format!("https://cvedb.shodan.io/cve/{cve_id}");
        let resp = client.get(&url).send().await.ok()?;
        if !resp.status().is_success() { return None; }
        let v: serde_json::Value = resp.json().await.ok()?;
        let info = CveInfo {
            cve: cve_id.to_string(),
            summary: v.get("summary").and_then(|s| s.as_str()).map(|s| s.to_string()),
            cvss: v.get("cvss").and_then(|c| c.as_f64()),
            cvss_v3: v.get("cvss_v3").and_then(|c| c.as_f64()),
            epss: v.get("epss").and_then(|e| e.as_f64()),
            kev: v.get("kev").and_then(|k| k.as_bool()).unwrap_or(false),
            references: v.get("references")
                .and_then(|r| r.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default(),
        };
        self.cve_cache.write().insert(
            cve_id.to_string(),
            CacheEntry { value: info.clone(), cached_at: std::time::Instant::now() },
        );
        Some(info)
    }

    pub async fn search(&self, query: &str, page: usize) -> Option<Vec<HostInfo>> {
        let k = self.api_key.as_ref()?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .ok()?;
        let url = format!(
            "https://api.shodan.io/shodan/host/search?key={}&query={}&page={}",
            k,
            urlencoding(query),
            page
        );
        let resp = client.get(&url).send().await.ok()?;
        if !resp.status().is_success() { return None; }
        let v: serde_json::Value = resp.json().await.ok()?;
        let matches = v.get("matches").and_then(|m| m.as_array())?;
        let mut out = Vec::new();
        for m in matches {
            if let Some(ip) = m.get("ip_str").and_then(|i| i.as_str()) {
                out.push(self.parse_shodan_match(ip, m));
            }
        }
        Some(out)
    }

    async fn fetch_shodan_host(&self, ip: &str, key: &str) -> Option<HostInfo> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .ok()?;
        let url = format!("https://api.shodan.io/shodan/host/{ip}?key={key}");
        let resp = client.get(&url).send().await.ok()?;
        if !resp.status().is_success() { return None; }
        let v: serde_json::Value = resp.json().await.ok()?;
        Some(self.parse_shodan_match(ip, &v))
    }

    fn parse_shodan_match(&self, ip: &str, v: &serde_json::Value) -> HostInfo {
        let take_strs = |k: &str| -> Vec<String> {
            v.get(k).and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default()
        };
        HostInfo {
            ip: ip.to_string(),
            hostnames: take_strs("hostnames"),
            ports: v.get("ports").and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as u16)).collect())
                .unwrap_or_default(),
            vulns: take_strs("vulns"),
            os: v.get("os").and_then(|o| o.as_str()).map(|s| s.to_string()),
            tags: take_strs("tags"),
            last_update: v.get("last_update").and_then(|l| l.as_str()).map(|s| s.to_string()),
            org: v.get("org").and_then(|o| o.as_str()).map(|s| s.to_string()),
            country: v.get("country_name").and_then(|c| c.as_str()).map(|s| s.to_string()),
            source: HostSource::Shodan,
            fetched_at: chrono::Utc::now(),
        }
    }

    async fn fetch_internetdb(&self, ip: &str) -> Option<HostInfo> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .ok()?;
        let url = format!("https://internetdb.shodan.io/{ip}");
        let resp = client.get(&url).send().await.ok()?;
        if !resp.status().is_success() { return None; }
        let v: serde_json::Value = resp.json().await.ok()?;
        let take_strs = |k: &str| -> Vec<String> {
            v.get(k).and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default()
        };
        Some(HostInfo {
            ip: ip.to_string(),
            hostnames: take_strs("hostnames"),
            ports: v.get("ports").and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as u16)).collect())
                .unwrap_or_default(),
            vulns: take_strs("vulns"),
            os: None,
            tags: take_strs("tags"),
            last_update: None,
            org: None,
            country: None,
            source: HostSource::InternetDb,
            fetched_at: chrono::Utc::now(),
        })
    }
}

fn urlencoding(s: &str) -> String {
    s.chars().map(|c| match c {
        'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
        ' ' => "%20".to_string(),
        _ => {
            let mut buf = [0u8; 4];
            let bytes = c.encode_utf8(&mut buf).as_bytes().to_vec();
            bytes.iter().map(|b| format!("%{b:02X}")).collect()
        }
    }).collect()
}
