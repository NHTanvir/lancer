//! Parse OpenAPI 3.x and Postman collections into a flat list of requests
//! Lancer can iterate (scan, fuzz, store in the site map).

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use lancer_core::HttpRequest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedRequest {
    pub name: String,
    pub request: HttpRequest,
    pub tags: Vec<String>,
}

/// Parse an OpenAPI 3.x document (JSON or YAML) into requests.
pub fn parse_openapi(body: &str, default_base: Option<&str>) -> Result<Vec<ImportedRequest>> {
    let doc: serde_yaml::Value = serde_yaml::from_str(body)?;
    let servers = doc["servers"]
        .as_sequence()
        .map(|s| s.iter().filter_map(|v| v["url"].as_str().map(|s| s.to_string())).collect())
        .unwrap_or_else(Vec::new);
    let base = servers
        .first()
        .cloned()
        .or_else(|| default_base.map(|s| s.to_string()))
        .ok_or_else(|| anyhow!("openapi spec has no servers[] and no --base supplied"))?;

    let mut out = Vec::new();
    let paths = match doc["paths"].as_mapping() {
        Some(m) => m,
        None => return Ok(out),
    };
    for (path_v, ops) in paths {
        let raw_path = path_v.as_str().unwrap_or("/");
        let Some(ops_map) = ops.as_mapping() else { continue };
        for (verb_v, op) in ops_map {
            let verb = verb_v.as_str().unwrap_or("get").to_string();
            if !is_http_verb(&verb) {
                continue;
            }
            let url = format!("{}{}", base.trim_end_matches('/'), raw_path);
            let Ok(mut req) = HttpRequest::builder(verb.to_uppercase().as_str(), &url) else {
                continue;
            };
            // Insert placeholders for any required query/path params.
            if let Some(params) = op["parameters"].as_sequence() {
                for p in params {
                    let in_ = p["in"].as_str().unwrap_or("");
                    let name = p["name"].as_str().unwrap_or("").to_string();
                    let placeholder = "lancer_placeholder";
                    match in_ {
                        "query" => {
                            let sep = if req.path.contains('?') { "&" } else { "?" };
                            req.path.push_str(&format!("{sep}{name}={placeholder}"));
                        }
                        "header" => req.set_header(&name, placeholder),
                        "path" => {
                            req.path = req.path.replace(&format!("{{{name}}}"), placeholder);
                        }
                        _ => {}
                    }
                }
            }
            if let Some(req_body) = op["requestBody"].as_mapping() {
                let content = &req_body[&serde_yaml::Value::from("content")];
                if let Some(map) = content.as_mapping() {
                    if let Some((ct_v, _schema)) = map.iter().next() {
                        let ct = ct_v.as_str().unwrap_or("application/json");
                        req.set_header("Content-Type", ct);
                        // We don't synthesise a schema — leave body empty.
                    }
                }
            }
            let mut tags: Vec<String> = op["tags"]
                .as_sequence()
                .map(|s| s.iter().filter_map(|t| t.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            tags.push("openapi".to_string());
            let name = op["operationId"]
                .as_str()
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{verb} {raw_path}"));
            out.push(ImportedRequest { name, request: req, tags });
        }
    }
    Ok(out)
}

/// Parse a Postman v2.1 collection into requests.
pub fn parse_postman(body: &str) -> Result<Vec<ImportedRequest>> {
    let doc: serde_json::Value = serde_json::from_str(body)?;
    let mut env: HashMap<String, String> = HashMap::new();
    if let Some(vars) = doc["variable"].as_array() {
        for v in vars {
            if let (Some(k), Some(val)) = (v["key"].as_str(), v["value"].as_str()) {
                env.insert(k.to_string(), val.to_string());
            }
        }
    }
    let mut out = Vec::new();
    if let Some(items) = doc["item"].as_array() {
        for item in items {
            walk_postman(item, &env, &[], &mut out);
        }
    }
    Ok(out)
}

fn walk_postman(
    item: &serde_json::Value,
    env: &HashMap<String, String>,
    parent_folders: &[String],
    out: &mut Vec<ImportedRequest>,
) {
    let name = item["name"].as_str().unwrap_or("").to_string();
    if let Some(sub) = item["item"].as_array() {
        let mut folder = parent_folders.to_vec();
        folder.push(name);
        for s in sub {
            walk_postman(s, env, &folder, out);
        }
        return;
    }
    let req = match item["request"].as_object() {
        Some(o) => o,
        None => return,
    };
    let method = req
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .to_string();
    let url_str = match req.get("url") {
        Some(serde_json::Value::String(s)) => substitute_env(s, env),
        Some(serde_json::Value::Object(o)) => o
            .get("raw")
            .and_then(|v| v.as_str())
            .map(|s| substitute_env(s, env))
            .unwrap_or_default(),
        _ => return,
    };
    if url_str.is_empty() {
        return;
    }
    let Ok(mut http_req) = HttpRequest::builder(method.to_uppercase().as_str(), &url_str) else {
        return;
    };
    if let Some(headers) = req.get("header").and_then(|h| h.as_array()) {
        for h in headers {
            if let (Some(k), Some(v)) = (h["key"].as_str(), h["value"].as_str()) {
                http_req.set_header(k, substitute_env(v, env));
            }
        }
    }
    if let Some(body) = req.get("body").and_then(|b| b.as_object()) {
        if let Some(raw) = body.get("raw").and_then(|v| v.as_str()) {
            http_req.body = Bytes::from(substitute_env(raw, env));
        }
    }
    let mut tags: Vec<String> = parent_folders.to_vec();
    tags.push("postman".to_string());
    out.push(ImportedRequest { name, request: http_req, tags });
}

fn substitute_env(s: &str, env: &HashMap<String, String>) -> String {
    let mut out = s.to_string();
    for (k, v) in env {
        out = out.replace(&format!("{{{{{k}}}}}"), v);
    }
    out
}

fn is_http_verb(s: &str) -> bool {
    matches!(
        s.to_lowercase().as_str(),
        "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
    )
}
