//! Shared cookie jar.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use lancer_core::HttpResponse;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub domain: String,
    pub path: String,
    pub name: String,
    pub value: String,
    pub expires: Option<DateTime<Utc>>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<SameSite>,
}

impl Cookie {
    pub fn key(&self) -> String {
        format!("{}|{}|{}", self.domain, self.path, self.name)
    }
}

#[derive(Default, Debug)]
pub struct CookieJar {
    inner: Arc<RwLock<HashMap<String, Cookie>>>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clone_handle(&self) -> Self {
        Self { inner: self.inner.clone() }
    }

    pub fn add(&self, cookie: Cookie) {
        self.inner.write().insert(cookie.key(), cookie);
    }

    pub fn remove(&self, key: &str) {
        self.inner.write().remove(key);
    }

    pub fn clear(&self) {
        self.inner.write().clear();
    }

    /// Pull cookies that should be attached to a request against `host`/`path`.
    pub fn for_request(&self, host: &str, path: &str, is_https: bool) -> Vec<Cookie> {
        let now = Utc::now();
        self.inner
            .read()
            .values()
            .filter(|c| {
                let domain_ok = host == c.domain
                    || (c.domain.starts_with('.') && host.ends_with(&c.domain[1..]));
                let path_ok = path.starts_with(&c.path);
                let secure_ok = !c.secure || is_https;
                let not_expired = c
                    .expires
                    .map(|e| e > now)
                    .unwrap_or(true);
                domain_ok && path_ok && secure_ok && not_expired
            })
            .cloned()
            .collect()
    }

    /// Extract every Set-Cookie line from a response and store the result.
    pub fn ingest_response(&self, response: &HttpResponse, default_domain: &str) {
        for h in &response.headers {
            if !h.name.eq_ignore_ascii_case("Set-Cookie") {
                continue;
            }
            if let Some(c) = parse_set_cookie(&h.value, default_domain) {
                self.add(c);
            }
        }
    }

    pub fn all(&self) -> Vec<Cookie> {
        self.inner.read().values().cloned().collect()
    }
}

fn parse_set_cookie(value: &str, default_domain: &str) -> Option<Cookie> {
    let mut parts = value.split(';');
    let first = parts.next()?.trim();
    let (name, val) = first.split_once('=')?;
    let mut cookie = Cookie {
        domain: default_domain.to_string(),
        path: "/".to_string(),
        name: name.trim().to_string(),
        value: val.trim().to_string(),
        expires: None,
        secure: false,
        http_only: false,
        same_site: None,
    };
    for part in parts {
        let part = part.trim();
        let (k, v) = part.split_once('=').map(|(a, b)| (a.to_ascii_lowercase(), b.to_string())).unwrap_or((part.to_ascii_lowercase(), String::new()));
        match k.as_str() {
            "domain" => cookie.domain = v,
            "path" => cookie.path = v,
            "secure" => cookie.secure = true,
            "httponly" => cookie.http_only = true,
            "samesite" => {
                cookie.same_site = match v.to_ascii_lowercase().as_str() {
                    "strict" => Some(SameSite::Strict),
                    "lax" => Some(SameSite::Lax),
                    "none" => Some(SameSite::None),
                    _ => None,
                };
            }
            "expires" => {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(&v) {
                    cookie.expires = Some(dt.with_timezone(&Utc));
                }
            }
            _ => {}
        }
    }
    Some(cookie)
}
