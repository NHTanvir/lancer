//! Suite scope (target inclusion / exclusion) — used by every tool.

use std::str::FromStr;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::http_msg::HttpRequest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeRuleKind {
    Include,
    Exclude,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeRule {
    pub kind: ScopeRuleKind,
    pub protocol: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub path: Option<String>,
    pub enabled: bool,
    /// If true, host/path are interpreted as a full regex; otherwise wildcards
    /// (`*`) are translated to `.*` and the rest is literal.
    pub regex: bool,
}

impl ScopeRule {
    pub fn matches(&self, req: &HttpRequest) -> bool {
        if !self.enabled {
            return false;
        }
        if let Some(proto) = &self.protocol {
            if !req.meta.scheme.eq_ignore_ascii_case(proto) {
                return false;
            }
        }
        if let Some(port) = self.port {
            if req.meta.port != port {
                return false;
            }
        }
        if !match_pattern(&self.host, &req.meta.host, self.regex) {
            return false;
        }
        if let Some(path) = &self.path {
            let path_only = req.path.split('?').next().unwrap_or(&req.path);
            if !match_pattern(path, path_only, self.regex) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub rules: Vec<ScopeRule>,
    /// If the include-list is empty, treat everything as in-scope (unless excluded).
    pub default_include: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeMatch {
    Included,
    Excluded,
    NoMatch,
}

impl Scope {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, rule: ScopeRule) {
        self.rules.push(rule);
    }

    pub fn check(&self, req: &HttpRequest) -> ScopeMatch {
        let mut included = false;
        let mut any_include = false;
        for rule in &self.rules {
            if rule.kind == ScopeRuleKind::Include {
                any_include = true;
                if rule.matches(req) {
                    included = true;
                }
            }
        }
        for rule in &self.rules {
            if rule.kind == ScopeRuleKind::Exclude && rule.matches(req) {
                return ScopeMatch::Excluded;
            }
        }
        if included {
            ScopeMatch::Included
        } else if !any_include && self.default_include {
            ScopeMatch::Included
        } else {
            ScopeMatch::NoMatch
        }
    }

    pub fn is_in_scope(&self, req: &HttpRequest) -> bool {
        matches!(self.check(req), ScopeMatch::Included)
    }
}

fn match_pattern(pattern: &str, value: &str, regex_mode: bool) -> bool {
    if regex_mode {
        return Regex::new(pattern).map(|r| r.is_match(value)).unwrap_or(false);
    }
    if pattern.contains('*') {
        let mut translated = String::with_capacity(pattern.len() * 2 + 8);
        translated.push('^');
        for c in pattern.chars() {
            if c == '*' {
                translated.push_str(".*");
            } else if matches!(c, '.' | '+' | '(' | ')' | '?' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\') {
                translated.push('\\');
                translated.push(c);
            } else {
                translated.push(c);
            }
        }
        translated.push('$');
        return Regex::new(&translated).map(|r| r.is_match(value)).unwrap_or(false);
    }
    value.eq_ignore_ascii_case(pattern)
}

impl FromStr for ScopeRule {
    type Err = Error;

    /// Parse a shorthand of the form:
    ///
    ///   `https://*.example.com:443/api/*`
    ///   `http://*.test.com`
    ///   `*.evil.com`
    fn from_str(s: &str) -> Result<Self> {
        let (protocol, rest) = if let Some((proto, rest)) = s.split_once("://") {
            (Some(proto.to_string()), rest.to_string())
        } else {
            (None, s.to_string())
        };
        let (host_port, path) = match rest.find('/') {
            Some(i) => (rest[..i].to_string(), Some(rest[i..].to_string())),
            None => (rest, None),
        };
        let (host, port) = if host_port.starts_with('[') {
            // Bracketed IPv6 literal: only a ':' AFTER the closing ']' is a port separator.
            match host_port.find(']') {
                Some(close) => {
                    let h = host_port[..=close].to_string();
                    let rest = &host_port[close + 1..];
                    let port = match rest.strip_prefix(':') {
                        Some(p) => Some(
                            p.parse::<u16>()
                                .map_err(|_| Error::InvalidScope(format!("bad port in {s}")))?,
                        ),
                        None if rest.is_empty() => None,
                        None => return Err(Error::InvalidScope(format!("bad host in {s}"))),
                    };
                    (h, port)
                }
                None => {
                    return Err(Error::InvalidScope(format!("unterminated IPv6 literal in {s}")))
                }
            }
        } else {
            match host_port.rfind(':') {
                Some(i) => {
                    let h = host_port[..i].to_string();
                    let p = host_port[i + 1..]
                        .parse::<u16>()
                        .map_err(|_| Error::InvalidScope(format!("bad port in {s}")))?;
                    (h, Some(p))
                }
                None => (host_port, None),
            }
        };
        Ok(ScopeRule {
            kind: ScopeRuleKind::Include,
            protocol,
            host,
            port,
            path,
            enabled: true,
            regex: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_msg::HttpRequest;

    fn req(url: &str) -> HttpRequest {
        HttpRequest::builder("GET", url).unwrap()
    }

    #[test]
    fn wildcard_host() {
        let rule: ScopeRule = "https://*.example.com".parse().unwrap();
        assert!(rule.matches(&req("https://api.example.com/x")));
        assert!(rule.matches(&req("https://www.example.com/")));
        assert!(!rule.matches(&req("https://evil.com/")));
    }

    #[test]
    fn include_exclude_combo() {
        let mut scope = Scope::new();
        scope.add("https://*.example.com".parse().unwrap());
        let mut excl: ScopeRule = "https://logout.example.com".parse().unwrap();
        excl.kind = ScopeRuleKind::Exclude;
        scope.add(excl);

        assert_eq!(scope.check(&req("https://api.example.com/")), ScopeMatch::Included);
        assert_eq!(scope.check(&req("https://logout.example.com/")), ScopeMatch::Excluded);
        assert_eq!(scope.check(&req("https://other.com/")), ScopeMatch::NoMatch);
    }

    #[test]
    fn default_include() {
        let mut scope = Scope::new();
        scope.default_include = true;
        let mut excl: ScopeRule = "https://*.bad.com".parse().unwrap();
        excl.kind = ScopeRuleKind::Exclude;
        scope.add(excl);
        assert!(scope.is_in_scope(&req("https://x.com/")));
        assert!(!scope.is_in_scope(&req("https://api.bad.com/")));
    }
}
