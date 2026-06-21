//! Match-and-replace rules applied to flowing traffic.
//!
//! Lightweight; designed to be re-applied on every request/response. Rules can
//! target:
//! - request header
//! - request body
//! - request first line (method + path + version)
//! - response header
//! - response body
//! - response first line (version + status + reason)

use std::sync::Arc;

use arc_swap::ArcSwap;
use lancer_core::{HttpRequest, HttpResponse};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchTarget {
    RequestHeader,
    RequestBody,
    RequestFirstLine,
    ResponseHeader,
    ResponseBody,
    ResponseFirstLine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchReplaceRule {
    pub name: String,
    pub enabled: bool,
    pub target: MatchTarget,
    pub pattern: String,
    pub replacement: String,
    pub is_regex: bool,
    pub only_in_scope: bool,
}

impl MatchReplaceRule {
    fn apply_to_string(&self, s: &str) -> Option<String> {
        if self.is_regex {
            let rx = Regex::new(&self.pattern).ok()?;
            if !rx.is_match(s) {
                return None;
            }
            Some(rx.replace_all(s, &self.replacement).into_owned())
        } else {
            if !s.contains(&self.pattern) {
                return None;
            }
            Some(s.replace(&self.pattern, &self.replacement))
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MatchReplaceConfig {
    pub rules: Vec<MatchReplaceRule>,
}

#[derive(Debug, Clone, Default)]
pub struct MatchReplaceEngine {
    config: Arc<ArcSwap<MatchReplaceConfig>>,
}

impl MatchReplaceEngine {
    pub fn new(cfg: MatchReplaceConfig) -> Self {
        Self { config: Arc::new(ArcSwap::from_pointee(cfg)) }
    }

    pub fn snapshot(&self) -> Arc<MatchReplaceConfig> {
        self.config.load_full()
    }

    pub fn replace(&self, cfg: MatchReplaceConfig) {
        self.config.store(Arc::new(cfg));
    }

    pub fn apply_request(&self, req: &mut HttpRequest, in_scope: bool) -> usize {
        let cfg = self.snapshot();
        let mut hits = 0;
        for rule in &cfg.rules {
            if !rule.enabled {
                continue;
            }
            if rule.only_in_scope && !in_scope {
                continue;
            }
            match rule.target {
                MatchTarget::RequestHeader => {
                    for h in req.headers.iter_mut() {
                        let line = format!("{}: {}", h.name, h.value);
                        if let Some(new_line) = rule.apply_to_string(&line) {
                            if let Some((n, v)) = new_line.split_once(':') {
                                h.name = n.trim().to_string();
                                h.value = v.trim().to_string();
                                hits += 1;
                            }
                        }
                    }
                }
                MatchTarget::RequestBody => {
                    if let Ok(body) = std::str::from_utf8(&req.body) {
                        if let Some(new_body) = rule.apply_to_string(body) {
                            req.body = bytes::Bytes::from(new_body);
                            hits += 1;
                        }
                    }
                }
                MatchTarget::RequestFirstLine => {
                    let line = format!(
                        "{} {} {}",
                        req.method.as_str(),
                        req.path,
                        req.version
                    );
                    if let Some(new_line) = rule.apply_to_string(&line) {
                        let mut parts = new_line.splitn(3, ' ');
                        if let (Some(m), Some(p)) = (parts.next(), parts.next()) {
                            req.method = lancer_core::SerializableMethod::from(m);
                            req.path = p.to_string();
                            if let Some(v) = parts.next() {
                                match v.trim() {
                                    "HTTP/0.9" => req.version = lancer_core::HttpVersion::Http09,
                                    "HTTP/1.0" => req.version = lancer_core::HttpVersion::Http10,
                                    "HTTP/1.1" => req.version = lancer_core::HttpVersion::Http11,
                                    "HTTP/2" | "HTTP/2.0" => req.version = lancer_core::HttpVersion::Http2,
                                    "HTTP/3" => req.version = lancer_core::HttpVersion::Http3,
                                    _ => {}
                                }
                            }
                            hits += 1;
                        }
                    }
                }
                _ => {}
            }
        }
        hits
    }

    pub fn apply_response(&self, resp: &mut HttpResponse, in_scope: bool) -> usize {
        let cfg = self.snapshot();
        let mut hits = 0;
        for rule in &cfg.rules {
            if !rule.enabled {
                continue;
            }
            if rule.only_in_scope && !in_scope {
                continue;
            }
            match rule.target {
                MatchTarget::ResponseHeader => {
                    for h in resp.headers.iter_mut() {
                        let line = format!("{}: {}", h.name, h.value);
                        if let Some(new_line) = rule.apply_to_string(&line) {
                            if let Some((n, v)) = new_line.split_once(':') {
                                h.name = n.trim().to_string();
                                h.value = v.trim().to_string();
                                hits += 1;
                            }
                        }
                    }
                }
                MatchTarget::ResponseBody => {
                    if let Ok(body) = std::str::from_utf8(&resp.body) {
                        if let Some(new_body) = rule.apply_to_string(body) {
                            resp.body = bytes::Bytes::from(new_body);
                            hits += 1;
                        }
                    }
                }
                MatchTarget::ResponseFirstLine => {
                    let line = format!(
                        "{} {} {}",
                        resp.version, resp.status, resp.reason
                    );
                    if let Some(new_line) = rule.apply_to_string(&line) {
                        let mut parts = new_line.splitn(3, ' ');
                        if let (Some(_v), Some(s)) = (parts.next(), parts.next()) {
                            if let Ok(code) = s.parse::<u16>() {
                                resp.status = code;
                            }
                            if let Some(reason) = parts.next() {
                                resp.reason = reason.to_string();
                            }
                            hits += 1;
                        }
                    }
                }
                _ => {}
            }
        }
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lancer_core::HttpRequest;

    #[test]
    fn replace_header_value() {
        let engine = MatchReplaceEngine::new(MatchReplaceConfig {
            rules: vec![MatchReplaceRule {
                name: "ua".into(),
                enabled: true,
                target: MatchTarget::RequestHeader,
                pattern: "User-Agent: .*".into(),
                replacement: "User-Agent: lancer".into(),
                is_regex: true,
                only_in_scope: false,
            }],
        });
        let mut req = HttpRequest::builder("GET", "https://x.com/").unwrap();
        req.set_header("User-Agent", "Mozilla/5.0");
        let hits = engine.apply_request(&mut req, true);
        assert_eq!(hits, 1);
        assert_eq!(req.header("User-Agent"), Some("lancer"));
    }
}
