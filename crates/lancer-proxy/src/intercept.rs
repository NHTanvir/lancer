//! Interception engine.
//!
//! Holds the runtime toggles for whether the proxy should pause inbound
//! requests / responses for user editing, plus the set of intercept rules.

use std::sync::Arc;

use arc_swap::ArcSwap;
use lancer_core::{HttpRequest, HttpResponse};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptDecision {
    /// Send to the user-supplied intercept handler (UI / CLI prompt).
    Pause,
    /// Forward unchanged.
    Forward,
    /// Drop the message; close the connection.
    Drop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptRule {
    pub name: String,
    pub enabled: bool,
    /// If true, this rule matches requests. If false, it matches responses.
    pub on_request: bool,
    /// Substring (case-insensitive) the URL must contain, if set.
    pub url_contains: Option<String>,
    /// Regex against the URL, if set.
    pub url_regex: Option<String>,
    /// HTTP method filter (request-only).
    pub method: Option<String>,
    /// Status filter (response-only).
    pub status: Option<u16>,
    /// What to do when matched.
    pub action: InterceptDecision,
}

impl InterceptRule {
    fn matches_request(&self, req: &HttpRequest) -> bool {
        if !self.enabled || !self.on_request {
            return false;
        }
        if let Some(m) = &self.method {
            if !req.method.as_str().eq_ignore_ascii_case(m) {
                return false;
            }
        }
        let url = req.url();
        if let Some(s) = &self.url_contains {
            if !url.to_lowercase().contains(&s.to_lowercase()) {
                return false;
            }
        }
        if let Some(rx) = &self.url_regex {
            if let Ok(r) = Regex::new(rx) {
                if !r.is_match(&url) {
                    return false;
                }
            }
        }
        true
    }

    fn matches_response(&self, resp: &HttpResponse) -> bool {
        if !self.enabled || self.on_request {
            return false;
        }
        if let Some(s) = self.status {
            if resp.status != s {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct InterceptConfig {
    pub intercept_requests: bool,
    pub intercept_responses: bool,
    pub rules: Vec<InterceptRule>,
}

/// Lock-free, cheaply cloneable interception engine.
#[derive(Debug, Clone)]
pub struct InterceptEngine {
    config: Arc<ArcSwap<InterceptConfig>>,
}

impl Default for InterceptEngine {
    fn default() -> Self {
        Self::new(InterceptConfig::default())
    }
}

impl InterceptEngine {
    pub fn new(config: InterceptConfig) -> Self {
        Self { config: Arc::new(ArcSwap::from_pointee(config)) }
    }

    pub fn snapshot(&self) -> Arc<InterceptConfig> {
        self.config.load_full()
    }

    pub fn replace(&self, config: InterceptConfig) {
        self.config.store(Arc::new(config));
    }

    pub fn toggle_request_interception(&self, on: bool) {
        let mut cfg = (*self.snapshot()).clone();
        cfg.intercept_requests = on;
        self.replace(cfg);
    }

    pub fn toggle_response_interception(&self, on: bool) {
        let mut cfg = (*self.snapshot()).clone();
        cfg.intercept_responses = on;
        self.replace(cfg);
    }

    pub fn decide_request(&self, req: &HttpRequest) -> InterceptDecision {
        let cfg = self.snapshot();
        for rule in &cfg.rules {
            if rule.matches_request(req) {
                return rule.action;
            }
        }
        if cfg.intercept_requests {
            InterceptDecision::Pause
        } else {
            InterceptDecision::Forward
        }
    }

    pub fn decide_response(&self, resp: &HttpResponse) -> InterceptDecision {
        let cfg = self.snapshot();
        for rule in &cfg.rules {
            if rule.matches_response(resp) {
                return rule.action;
            }
        }
        if cfg.intercept_responses {
            InterceptDecision::Pause
        } else {
            InterceptDecision::Forward
        }
    }
}
