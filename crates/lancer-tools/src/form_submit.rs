//! Form auto-submission for the crawler.
//!
//! Parses `<form>` elements out of an HTML body, synthesises sensible default
//! values for each `<input>` field, and returns an `HttpRequest` per form.

use lancer_core::HttpRequest;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredForm {
    pub method: String,
    pub action_url: String,
    pub fields: Vec<(String, String)>,
}

pub fn discover_forms(body: &str, base_url: &str) -> Vec<DiscoveredForm> {
    let form_rx = Regex::new(r#"(?is)<form\b([^>]*)>(.*?)</form>"#).unwrap();
    let attr_rx = Regex::new(r#"(?i)(\w+)\s*=\s*["']([^"']+)["']"#).unwrap();
    let input_rx = Regex::new(r#"(?i)<(input|select|textarea)\b([^>]*)/?>"#).unwrap();
    let mut out = Vec::new();
    for cap in form_rx.captures_iter(body) {
        let attrs = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let inner = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let mut method = "GET".to_string();
        let mut action = String::new();
        for ac in attr_rx.captures_iter(attrs) {
            let k = ac[1].to_ascii_lowercase();
            let v = ac[2].to_string();
            match k.as_str() {
                "method" => method = v.to_ascii_uppercase(),
                "action" => action = v,
                _ => {}
            }
        }
        let action_url = if action.is_empty() {
            base_url.to_string()
        } else if let Ok(base) = url::Url::parse(base_url) {
            base.join(&action).map(|u| u.to_string()).unwrap_or(action)
        } else {
            action
        };
        let mut fields = Vec::new();
        for input_cap in input_rx.captures_iter(inner) {
            let input_attrs = input_cap.get(2).map(|m| m.as_str()).unwrap_or("");
            let mut name = None;
            let mut value = None;
            let mut input_type = "text".to_string();
            for ac in attr_rx.captures_iter(input_attrs) {
                let k = ac[1].to_ascii_lowercase();
                let v = ac[2].to_string();
                match k.as_str() {
                    "name" => name = Some(v),
                    "value" => value = Some(v),
                    "type" => input_type = v.to_ascii_lowercase(),
                    _ => {}
                }
            }
            if let Some(n) = name {
                let v = value.unwrap_or_else(|| smart_default(&n, &input_type));
                fields.push((n, v));
            }
        }
        out.push(DiscoveredForm { method, action_url, fields });
    }
    out
}

fn smart_default(name: &str, input_type: &str) -> String {
    let lower = name.to_ascii_lowercase();
    match input_type {
        "email" => "lancer@example.com".into(),
        "number" => "1".into(),
        "tel" => "5550000".into(),
        "url" => "https://example.com/".into(),
        "password" => "Lancer123!".into(),
        "checkbox" | "radio" => "1".into(),
        "hidden" => String::new(),
        _ => {
            if lower.contains("email") {
                "lancer@example.com".into()
            } else if lower.contains("password") {
                "Lancer123!".into()
            } else if lower.contains("phone") {
                "5550000".into()
            } else if lower.contains("name") {
                "lancer".into()
            } else {
                "lancer".into()
            }
        }
    }
}

pub fn form_to_request(form: &DiscoveredForm) -> Option<HttpRequest> {
    let method = if form.method.eq_ignore_ascii_case("post") { "POST" } else { "GET" };
    let mut req = HttpRequest::builder(method, &form.action_url).ok()?;
    let body: String = form
        .fields
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    if method == "POST" {
        req.set_header("Content-Type", "application/x-www-form-urlencoded");
        req.set_header("Content-Length", body.len().to_string());
        req.body = bytes::Bytes::from(body);
    } else {
        let sep = if req.path.contains('?') { "&" } else { "?" };
        req.path.push_str(sep);
        req.path.push_str(&body);
    }
    Some(req)
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
