//! Insertion-point detection used by active checks.

use lancer_core::{HttpRequest, Inspector, ParamLocation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertionPoint {
    pub name: String,
    pub original_value: String,
    pub location: ParamLocation,
}

/// Walk a request and return every parameter that an active check could fuzz.
pub fn find_insertion_points(req: &HttpRequest) -> Vec<InsertionPoint> {
    let insp = Inspector::from_request(req);
    insp.params
        .into_iter()
        .map(|p| InsertionPoint {
            name: p.name,
            original_value: p.value,
            location: p.location,
        })
        .collect()
}

/// Produce a modified copy of `req` with `payload` substituted into the
/// insertion point. Returns `None` if the point can't be located cleanly.
pub fn substitute(req: &HttpRequest, point: &InsertionPoint, payload: &str) -> Option<HttpRequest> {
    let mut out = req.clone();
    out.meta.id = uuid::Uuid::new_v4();
    out.meta.tool_generated = true;
    match point.location {
        ParamLocation::Url => {
            replace_query_param(&mut out.path, &point.name, payload);
        }
        ParamLocation::Body => {
            let body = std::str::from_utf8(&out.body).ok()?.to_string();
            let new_body = replace_query_param_string(&body, &point.name, payload);
            out.body = bytes::Bytes::from(new_body);
        }
        ParamLocation::Cookie => {
            let cookie = out.header("Cookie")?.to_string();
            let new = replace_cookie_value(&cookie, &point.name, payload);
            out.set_header("Cookie", new);
        }
        ParamLocation::Header => {
            out.set_header(&point.name, payload);
        }
        ParamLocation::JsonValue | ParamLocation::JsonKey => {
            if let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&out.body) {
                json_set_by_dotted(&mut v, &point.name, payload);
                out.body = bytes::Bytes::from(serde_json::to_vec(&v).ok()?);
            }
        }
        _ => return None,
    }
    Some(out)
}

fn replace_query_param(path: &mut String, name: &str, value: &str) {
    if let Some((p, q)) = path.split_once('?') {
        let new_q = replace_query_param_string(q, name, value);
        *path = format!("{p}?{new_q}");
    }
}

fn replace_query_param_string(s: &str, name: &str, value: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut replaced = false;
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, _) = pair.split_once('=').unwrap_or((pair, ""));
        if k == name {
            parts.push(format!("{name}={value}"));
            replaced = true;
        } else {
            parts.push(pair.to_string());
        }
    }
    if !replaced {
        parts.push(format!("{name}={value}"));
    }
    parts.join("&")
}

fn replace_cookie_value(cookies: &str, name: &str, value: &str) -> String {
    let mut out = Vec::new();
    let mut replaced = false;
    for pair in cookies.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (k, _) = pair.split_once('=').unwrap_or((pair, ""));
        if k == name {
            out.push(format!("{name}={value}"));
            replaced = true;
        } else {
            out.push(pair.to_string());
        }
    }
    if !replaced {
        out.push(format!("{name}={value}"));
    }
    out.join("; ")
}

fn json_set_by_dotted(v: &mut serde_json::Value, dotted: &str, value: &str) {
    let parts: Vec<&str> = dotted.split('.').collect();
    json_set_inner(v, &parts, value);
}

fn json_set_inner(v: &mut serde_json::Value, parts: &[&str], value: &str) {
    if parts.is_empty() {
        *v = serde_json::Value::String(value.to_string());
        return;
    }
    let key = parts[0];
    let rest = &parts[1..];
    if let serde_json::Value::Object(map) = v {
        if let Some(child) = map.get_mut(key) {
            json_set_inner(child, rest, value);
        }
    }
}
