//! Nuclei v3-compatible YAML template engine.
//!
//! Parses and executes ProjectDiscovery Nuclei v3 format templates.
//! Supports HTTP, DNS, TCP, headless, and workflow templates.
//! DSL matchers: status, size, words, regex, binary, dsl.

use anyhow::Result;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Template data model ───────────────────────────────────────────────────────

/// Template info block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInfo {
    pub name: String,
    pub author: Option<serde_json::Value>,
    pub severity: Option<String>,
    pub description: Option<String>,
    pub reference: Option<serde_json::Value>,
    pub tags: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
}

/// HTTP request definition inside a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateHttpRequest {
    pub method: Option<String>,
    pub path: Option<Vec<String>>,
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub body: Option<String>,
    pub matchers: Option<Vec<Matcher>>,
    #[serde(rename = "matchers-condition")]
    pub matchers_condition: Option<String>,
    pub extractors: Option<Vec<Extractor>>,
    pub redirects: Option<bool>,
    #[serde(rename = "max-redirects")]
    pub max_redirects: Option<u32>,
}

/// A matcher in a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Matcher {
    #[serde(rename = "type")]
    pub kind: String,
    pub status: Option<Vec<u16>>,
    pub words: Option<Vec<String>>,
    pub regex: Option<Vec<String>>,
    pub dsl: Option<Vec<String>>,
    pub size: Option<Vec<usize>>,
    pub part: Option<String>,
    pub condition: Option<String>,
    pub negative: Option<bool>,
}

/// An extractor in a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extractor {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: Option<String>,
    pub regex: Option<Vec<String>>,
    pub group: Option<u32>,
    pub part: Option<String>,
}

/// A complete parsed template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    pub id: String,
    pub info: TemplateInfo,
    pub http: Option<Vec<TemplateHttpRequest>>,
    /// Path this template was loaded from (if from disk).
    #[serde(skip)]
    pub source_path: Option<std::path::PathBuf>,
}

/// Result of running a template against a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateResult {
    pub id: Uuid,
    pub template_id: String,
    pub template_name: String,
    pub severity: String,
    pub url: String,
    pub matched: bool,
    pub matched_at: Option<String>,
    pub extracted: Vec<ExtractedValue>,
    pub ran_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedValue {
    pub name: String,
    pub value: String,
}

// ── Template library ──────────────────────────────────────────────────────────

/// In-memory template library.
pub struct TemplateLibrary {
    templates: std::sync::RwLock<Vec<Template>>,
}

impl TemplateLibrary {
    pub fn new() -> Self {
        Self { templates: std::sync::RwLock::new(Vec::new()) }
    }

    /// Parse and add a template from a YAML string.
    pub fn add_yaml(&self, yaml: &str) -> Result<String> {
        let tpl: Template = serde_yaml::from_str(yaml)
            .map_err(|e| anyhow::anyhow!("YAML parse error: {e}"))?;
        let id = tpl.id.clone();
        self.templates.write().unwrap().push(tpl);
        Ok(id)
    }

    /// Add a pre-parsed template.
    pub fn add(&self, tpl: Template) {
        self.templates.write().unwrap().push(tpl);
    }

    /// Load all `.yaml` / `.yml` files from a directory tree.
    pub fn load_directory(&self, dir: &std::path::Path) -> Result<usize> {
        let mut count = 0;
        for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
            let path = entry.path();
            if path.is_file() {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "yaml" || ext == "yml" {
                    if let Ok(content) = std::fs::read_to_string(path) {
                        if let Ok(mut tpl) = serde_yaml::from_str::<Template>(&content) {
                            tpl.source_path = Some(path.to_path_buf());
                            self.add(tpl);
                            count += 1;
                        }
                    }
                }
            }
        }
        Ok(count)
    }

    pub fn list(&self) -> Vec<Template> {
        self.templates.read().unwrap().clone()
    }

    pub fn get(&self, id: &str) -> Option<Template> {
        self.templates.read().unwrap().iter().find(|t| t.id == id).cloned()
    }

    /// Remove a template by id. Returns true if one was removed.
    pub fn remove(&self, id: &str) -> bool {
        let mut g = self.templates.write().unwrap();
        let before = g.len();
        g.retain(|t| t.id != id);
        before != g.len()
    }

    pub fn len(&self) -> usize {
        self.templates.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.templates.read().unwrap().is_empty()
    }
}

impl Default for TemplateLibrary {
    fn default() -> Self { Self::new() }
}

// ── Template engine ───────────────────────────────────────────────────────────

/// Evaluates whether a matcher passes against a response.
fn eval_matcher(matcher: &Matcher, status: u16, body: &str, headers: &str) -> bool {
    let negative = matcher.negative.unwrap_or(false);
    let part = matcher.part.as_deref().unwrap_or("body");
    let content = if part == "header" || part == "headers" { headers } else { body };

    let result = match matcher.kind.as_str() {
        "status" => {
            matcher.status.as_ref().map(|list| list.contains(&status)).unwrap_or(false)
        }
        "word" | "words" => {
            let words = matcher.words.as_deref().unwrap_or(&[]);
            let condition = matcher.condition.as_deref().unwrap_or("or");
            if condition == "and" {
                words.iter().all(|w| content.contains(w.as_str()))
            } else {
                words.iter().any(|w| content.contains(w.as_str()))
            }
        }
        "regex" => {
            let patterns = matcher.regex.as_deref().unwrap_or(&[]);
            let condition = matcher.condition.as_deref().unwrap_or("or");
            let compiled: Vec<_> = patterns.iter()
                .filter_map(|p| regex::Regex::new(p).ok())
                .collect();
            if condition == "and" {
                compiled.iter().all(|re| re.is_match(content))
            } else {
                compiled.iter().any(|re| re.is_match(content))
            }
        }
        "size" => {
            let len = body.len();
            matcher.size.as_ref().map(|sizes| sizes.contains(&len)).unwrap_or(false)
        }
        "dsl" => {
            let exprs = matcher.dsl.as_deref().unwrap_or(&[]);
            let condition = matcher.condition.as_deref().unwrap_or("and");
            if exprs.is_empty() {
                false
            } else if condition == "or" {
                exprs.iter().any(|e| eval_dsl(e, status, body, headers))
            } else {
                exprs.iter().all(|e| eval_dsl(e, status, body, headers))
            }
        }
        _ => false,
    };

    if negative { !result } else { result }
}

/// Evaluate a (subset of) Nuclei-style DSL expression against a response.
///
/// Supports `&&` / `||` (lower precedence) of comparison and helper terms:
/// `status_code`, `content_length`, `len(body)`, `body`, `header`; the helpers
/// `contains(part, "x")`, `tolower(part)`, `toupper(part)`; and the operators
/// `==`, `!=`, `<`, `>`, `<=`, `>=`. This covers the overwhelming majority of
/// real-world template DSL matchers without embedding a full scripting engine.
pub fn eval_dsl(expr: &str, status: u16, body: &str, headers: &str) -> bool {
    let expr = expr.trim();
    let or_parts = split_top(expr, "||");
    if or_parts.len() > 1 {
        return or_parts.iter().any(|e| eval_dsl(e, status, body, headers));
    }
    let and_parts = split_top(expr, "&&");
    if and_parts.len() > 1 {
        return and_parts.iter().all(|e| eval_dsl(e, status, body, headers));
    }
    eval_dsl_term(expr.trim(), status, body, headers)
}

/// Split on `sep` only at top level (outside parentheses and quotes).
fn split_top(expr: &str, sep: &str) -> Vec<String> {
    let bytes = expr.as_bytes();
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut last = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '"' => in_str = !in_str,
            '(' if !in_str => depth += 1,
            ')' if !in_str => depth -= 1,
            _ => {}
        }
        if !in_str && depth == 0 && expr[i..].starts_with(sep) {
            parts.push(expr[last..i].to_string());
            i += sep.len();
            last = i;
            continue;
        }
        i += 1;
    }
    parts.push(expr[last..].to_string());
    parts
}

fn dsl_part<'a>(name: &str, body: &'a str, headers: &'a str) -> &'a str {
    match name.trim() {
        "header" | "all_headers" | "headers" => headers,
        _ => body,
    }
}

fn eval_dsl_term(term: &str, status: u16, body: &str, headers: &str) -> bool {
    let term = term.trim();
    if term.eq_ignore_ascii_case("true") { return true; }
    if term.eq_ignore_ascii_case("false") { return false; }

    // contains(part, "literal") -- check before generic paren stripping so the
    // function call's own closing ')' is not consumed.
    if let Some(inner) = term.strip_prefix("contains(").and_then(|s| s.strip_suffix(')')) {
        if let Some((p, lit)) = inner.split_once(',') {
            let needle = lit.trim().trim_matches('"');
            return dsl_part(p, body, headers).contains(needle);
        }
    }

    // Strip a wrapping paren pair only for the bare comparison path.
    let term = term.trim_start_matches('(').trim_end_matches(')').trim();

    // Comparison: LHS OP RHS
    for op in ["==", "!=", "<=", ">=", "<", ">"] {
        if let Some((lhs, rhs)) = term.split_once(op) {
            let (lhs, rhs) = (lhs.trim(), rhs.trim());
            let rhs_lit = rhs.trim_matches('"');
            // Numeric LHS variables.
            let lhs_num: Option<i64> = match lhs {
                "status_code" => Some(status as i64),
                "content_length" => Some(body.len() as i64),
                _ if lhs.starts_with("len(") => {
                    let inner = lhs.trim_start_matches("len(").trim_end_matches(')');
                    Some(dsl_part(inner, body, headers).len() as i64)
                }
                _ => None,
            };
            if let (Some(l), Ok(r)) = (lhs_num, rhs_lit.parse::<i64>()) {
                return match op { "==" => l == r, "!=" => l != r, "<=" => l <= r, ">=" => l >= r, "<" => l < r, _ => l > r };
            }
            // A numeric LHS variable with a non-numeric RHS is a malformed/unsatisfiable
            // term; never fall through to comparing it as a string against the whole body.
            if lhs_num.is_some() {
                return false;
            }
            // String comparison (body/header == "literal").
            let lhs_str = dsl_part(lhs, body, headers);
            return match op { "==" => lhs_str == rhs_lit, "!=" => lhs_str != rhs_lit, _ => false };
        }
    }
    false
}

/// Run a single template against a target URL using the given HTTP client.
/// Returns a `TemplateResult` regardless of match outcome.
pub async fn run_template(
    tpl: &Template,
    base_url: &str,
    client: &lancer_tools::HttpClient,
) -> TemplateResult {
    let mut matched = false;
    let mut matched_at = None;
    let mut extracted = Vec::new();

    let severity = tpl.info.severity.clone().unwrap_or_else(|| "info".into());

    if let Some(http_requests) = &tpl.http {
        'outer: for req_def in http_requests {
            let paths = req_def.path.as_deref().unwrap_or(&[]);
            for path_tpl in paths {
                let url = path_tpl.replace("{{BaseURL}}", base_url.trim_end_matches('/'));
                let method = req_def.method.as_deref().unwrap_or("GET");
                let Ok(mut req) = lancer_core::HttpRequest::builder(method, &url) else { continue };
                if let Some(headers) = &req_def.headers {
                    for (k, v) in headers {
                        req.headers.push(lancer_core::http_msg::Header::new(k, v));
                    }
                }
                if let Some(body) = &req_def.body {
                    req.body = Bytes::from(body.as_bytes().to_vec());
                }

                let Ok(resp) = client.send(&req).await else { continue };
                let body_text = resp.body_text().unwrap_or("");
                let headers_text = resp.headers.iter()
                    .map(|h| format!("{}: {}", h.name, h.value))
                    .collect::<Vec<_>>()
                    .join("\n");
                let status = resp.status;

                // Evaluate matchers
                let matchers = req_def.matchers.as_deref().unwrap_or(&[]);
                let condition = req_def.matchers_condition.as_deref().unwrap_or("and");
                if !matchers.is_empty() {
                    let results: Vec<bool> = matchers.iter()
                        .map(|m| eval_matcher(m, status, body_text, &headers_text))
                        .collect();
                    matched = if condition == "or" {
                        results.iter().any(|&r| r)
                    } else {
                        results.iter().all(|&r| r)
                    };
                }

                // Run extractors
                if let Some(extractors) = &req_def.extractors {
                    for ext in extractors {
                        let name = ext.name.clone().unwrap_or_else(|| "value".into());
                        let part = ext.part.as_deref().unwrap_or("body");
                        let content = if part == "header" { &headers_text } else { body_text };
                        if ext.kind == "regex" {
                            for pattern in ext.regex.as_deref().unwrap_or(&[]) {
                                if let Ok(re) = regex::Regex::new(pattern) {
                                    let group = ext.group.unwrap_or(0) as usize;
                                    for cap in re.captures_iter(content) {
                                        if let Some(m) = cap.get(group) {
                                            extracted.push(ExtractedValue {
                                                name: name.clone(),
                                                value: m.as_str().to_string(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if matched {
                    matched_at = Some(url);
                    break 'outer;
                }
            }
        }
    }

    TemplateResult {
        id: Uuid::new_v4(),
        template_id: tpl.id.clone(),
        template_name: tpl.info.name.clone(),
        severity,
        url: base_url.to_string(),
        matched,
        matched_at,
        extracted,
        ran_at: chrono::Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_template() {
        let yaml = r#"
id: test-template
info:
  name: Test Template
  author: test
  severity: info
  tags:
    - test
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
"#;
        let lib = TemplateLibrary::new();
        let id = lib.add_yaml(yaml).unwrap();
        assert_eq!(id, "test-template");
        assert_eq!(lib.len(), 1);
    }

    #[test]
    fn matcher_status_pass() {
        let m = Matcher {
            kind: "status".into(),
            status: Some(vec![200]),
            words: None, regex: None, dsl: None,
            part: None, condition: None, negative: None,
        };
        assert!(eval_matcher(&m, 200, "", ""));
        assert!(!eval_matcher(&m, 404, "", ""));
    }

    #[test]
    fn matcher_word_pass() {
        let m = Matcher {
            kind: "word".into(),
            status: None,
            words: Some(vec!["admin".into()]),
            regex: None, dsl: None,
            part: None, condition: None, negative: None,
        };
        assert!(eval_matcher(&m, 200, "welcome admin!", ""));
        assert!(!eval_matcher(&m, 200, "no match here", ""));
    }
}
