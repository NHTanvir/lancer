//! Engagement Tools — power-user one-shot analyses available from the
//! right-click menu in the GUI.
//!
//! Implemented:
//! - find_comments: scan response bodies for HTML / JS comments.
//! - find_scripts: extract all referenced script URLs from HTML.
//! - find_references: locate where a URL is linked from in stored history.
//! - generate_csrf_poc: produce a self-submitting HTML form for a request.
//! - discover_content: forced-browsing helper (wordlist + concurrency).
//! - search_across: simple substring search across captured messages.

use std::sync::Arc;

use anyhow::Result;
use lancer_core::{HttpRequest, HttpResponse};
use lancer_storage::HistoryStore;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::client::HttpClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentHit {
    pub url: String,
    pub kind: CommentKind,
    pub snippet: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommentKind {
    Html,
    JsLine,
    JsBlock,
}

pub fn find_comments(url: &str, body: &str) -> Vec<CommentHit> {
    let mut out = Vec::new();
    // HTML <!-- ... -->
    if let Ok(rx) = Regex::new(r"(?s)<!--(.*?)-->") {
        for cap in rx.captures_iter(body) {
            if let Some(m) = cap.get(1) {
                out.push(CommentHit {
                    url: url.to_string(),
                    kind: CommentKind::Html,
                    snippet: m.as_str().trim().to_string(),
                });
            }
        }
    }
    // JS // line
    if let Ok(rx) = Regex::new(r"(?m)//[^\n\r]*") {
        for m in rx.find_iter(body) {
            out.push(CommentHit {
                url: url.to_string(),
                kind: CommentKind::JsLine,
                snippet: m.as_str().to_string(),
            });
        }
    }
    // JS /* ... */
    if let Ok(rx) = Regex::new(r"(?s)/\*(.*?)\*/") {
        for cap in rx.captures_iter(body) {
            if let Some(m) = cap.get(1) {
                out.push(CommentHit {
                    url: url.to_string(),
                    kind: CommentKind::JsBlock,
                    snippet: m.as_str().trim().to_string(),
                });
            }
        }
    }
    out
}

pub fn find_scripts(body: &str, base_url: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(rx) = Regex::new(r#"<script[^>]*\s+src\s*=\s*["']([^"']+)["']"#) {
        for cap in rx.captures_iter(body) {
            if let Some(m) = cap.get(1) {
                let raw = m.as_str();
                if let Ok(base) = url::Url::parse(base_url) {
                    if let Ok(joined) = base.join(raw) {
                        out.push(joined.to_string());
                        continue;
                    }
                }
                out.push(raw.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfPoc {
    pub html: String,
}

/// Generate a self-submitting HTML form PoC for a state-changing request.
/// Supports application/x-www-form-urlencoded and multipart/form-data bodies.
pub fn generate_csrf_poc(req: &HttpRequest) -> CsrfPoc {
    use lancer_core::http_msg::MimeKind;
    let mut html = String::new();
    html.push_str("<!doctype html><html><body>\n");
    let mime = req
        .header("Content-Type")
        .map(MimeKind::from_content_type)
        .unwrap_or(MimeKind::FormUrlEncoded);
    // Use a canonical enctype keyword — never the raw Content-Type header, whose
    // `; boundary=...` suffix is an invalid HTML form enctype.
    let enctype = match mime {
        MimeKind::Multipart => "multipart/form-data",
        _ => "application/x-www-form-urlencoded",
    };
    html.push_str(&format!(
        "<form name=\"csrf\" action=\"{}\" method=\"{}\" enctype=\"{}\">\n",
        req.url(),
        req.method.as_str(),
        enctype,
    ));
    match mime {
        MimeKind::FormUrlEncoded => {
            if let Ok(body) = std::str::from_utf8(&req.body) {
                for pair in body.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        // Values in the wire body are percent-encoded; decode so the
                        // browser re-encodes them back to the original form on submit.
                        let dk = decode_form_component(k);
                        let dv = decode_form_component(v);
                        html.push_str(&format!(
                            "  <input type=\"hidden\" name=\"{}\" value=\"{}\" />\n",
                            html_escape(&dk),
                            html_escape(&dv),
                        ));
                    }
                }
            }
        }
        MimeKind::Multipart => {
            if let Some(boundary) = req
                .header("Content-Type")
                .and_then(|ct| ct.split("boundary=").nth(1))
                .map(|b| b.trim().trim_matches('"').to_string())
            {
                if let Ok(body) = std::str::from_utf8(&req.body) {
                    let delim = format!("--{}", boundary);
                    for part in body.split(&delim) {
                        let part = part.trim_start_matches("\r\n");
                        // split headers / value on the first blank line
                        if let Some((headers, value)) = part.split_once("\r\n\r\n") {
                            // only simple form-data text parts (no filename)
                            let lower = headers.to_ascii_lowercase();
                            if lower.contains("filename=") {
                                continue;
                            }
                            if let Some(name) = headers
                                .split("name=")
                                .nth(1)
                                .and_then(|s| s.split('"').nth(1))
                            {
                                let value = value.trim_end_matches("\r\n");
                                html.push_str(&format!(
                                    "  <input type=\"hidden\" name=\"{}\" value=\"{}\" />\n",
                                    html_escape(name),
                                    html_escape(value),
                                ));
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    html.push_str("  <input type=\"submit\" value=\"Submit\" />\n");
    html.push_str("</form>\n");
    html.push_str("<script>document.forms.csrf.submit();</script>\n");
    html.push_str("</body></html>\n");
    CsrfPoc { html }
}

fn decode_form_component(s: &str) -> String {
    // application/x-www-form-urlencoded uses '+' for space.
    let s = s.replace('+', " ");
    percent_encoding::percent_decode_str(&s).decode_utf8_lossy().into_owned()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Search across stored history for the given needle.
pub async fn search_across(history: &HistoryStore, needle: &str) -> Result<Vec<String>> {
    let rows = history
        .list(&lancer_storage::HistoryFilter {
            search: Some(needle.to_string()),
            limit: Some(500),
            ..Default::default()
        })
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| format!("{} {}://{}{}", r.method, r.scheme, r.host, r.path))
        .collect())
}

/// Locate every captured message whose body or URL references the given URL.
pub async fn find_references(history: &HistoryStore, url: &str) -> Result<Vec<uuid::Uuid>> {
    let rows = history.list(&lancer_storage::HistoryFilter {
        search: Some(url.to_string()),
        limit: Some(2000),
        ..Default::default()
    }).await?;
    let mut out = Vec::new();
    for row in rows {
        if let Some(body) = row.response.as_ref().and_then(|r| r.body_text()) {
            if body.contains(url) {
                out.push(row.id);
            }
        }
        if row.path.contains(url) {
            out.push(row.id);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Discover content — forced-browsing helper. Given a base URL and a wordlist
/// iterator, issue GETs and record any non-404 responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryHit {
    pub url: String,
    pub status: u16,
    pub length: usize,
}

pub async fn discover_content(
    client: HttpClient,
    base: &str,
    wordlist: impl Iterator<Item = String> + Send,
    concurrency: usize,
) -> Result<Vec<DiscoveryHit>> {
    let base_url = url::Url::parse(base)?;
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::new();
    for word in wordlist {
        let candidate = match base_url.join(&word) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let permit = sem.clone().acquire_owned().await?;
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let req = HttpRequest::builder("GET", candidate.as_str()).ok()?;
            let resp = client.send(&req).await.ok()?;
            if resp.status != 404 {
                Some(DiscoveryHit {
                    url: candidate.to_string(),
                    status: resp.status,
                    length: resp.body.len(),
                })
            } else {
                None
            }
        }));
    }
    let mut out = Vec::new();
    for h in handles {
        if let Ok(Some(hit)) = h.await {
            out.push(hit);
        }
    }
    Ok(out)
}

/// Extract anchor href URLs from an HTML body. Useful for crawl planning.
pub fn find_anchors(body: &str, base_url: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(rx) = Regex::new(r#"<a[^>]*\s+href\s*=\s*["']([^"']+)["']"#) {
        for cap in rx.captures_iter(body) {
            if let Some(m) = cap.get(1) {
                let raw = m.as_str();
                if let Ok(base) = url::Url::parse(base_url) {
                    if let Ok(joined) = base.join(raw) {
                        out.push(joined.to_string());
                        continue;
                    }
                }
                out.push(raw.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Target analyzer summary: counts of URLs, parameters, MIME types.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TargetAnalysis {
    pub url_count: usize,
    pub parameter_names: std::collections::BTreeSet<String>,
    pub host_count: usize,
    pub mime_counts: std::collections::BTreeMap<String, usize>,
}

pub async fn analyze_target(history: &HistoryStore) -> Result<TargetAnalysis> {
    use lancer_core::Inspector;
    let rows = history
        .list(&lancer_storage::HistoryFilter {
            limit: Some(10_000),
            ..Default::default()
        })
        .await?;
    let mut hosts = std::collections::BTreeSet::new();
    let mut params = std::collections::BTreeSet::new();
    let mut mimes = std::collections::BTreeMap::new();
    let url_count = rows.len();
    for r in &rows {
        hosts.insert(r.host.clone());
        let insp = Inspector::from_request(&r.request);
        for p in &insp.params {
            params.insert(p.name.clone());
        }
        if let Some(m) = &r.mime {
            *mimes.entry(m.clone()).or_insert(0) += 1;
        }
    }
    Ok(TargetAnalysis {
        url_count,
        parameter_names: params,
        host_count: hosts.len(),
        mime_counts: mimes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_html_comments() {
        let body = "<html><!-- secret: 1234 -->hello<!--another--></html>";
        let hits = find_comments("https://x.com/", body);
        assert_eq!(hits.iter().filter(|h| h.kind == CommentKind::Html).count(), 2);
    }

    #[test]
    fn finds_scripts() {
        let body = "<html><script src=\"/static/main.js\"></script><script src=\"https://cdn.example.com/lib.js\"></script></html>";
        let s = find_scripts(body, "https://x.com/");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn csrf_poc_form_url_encoded() {
        let mut req = lancer_core::HttpRequest::builder("POST", "https://x.com/login").unwrap();
        req.set_header("Content-Type", "application/x-www-form-urlencoded");
        req.body = bytes::Bytes::from_static(b"user=alice&pass=hunter2");
        let poc = generate_csrf_poc(&req);
        assert!(poc.html.contains("name=\"user\""));
        assert!(poc.html.contains("name=\"pass\""));
        assert!(poc.html.contains("forms.csrf.submit()"));
    }
}
