//! Multi-step macros — record a sequence of requests, replay them on demand.

use anyhow::Result;
use lancer_core::{HttpRequest, HttpResponse};
use lancer_tools::HttpClient;
use regex::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroStep {
    pub request: HttpRequest,
    /// Extractions to pull from the response and feed into later steps.
    pub extracts: Vec<MacroExtract>,
    /// Substitutions to apply to *this* step's request from previously
    /// extracted values.
    pub substitutions: Vec<MacroSub>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroExtract {
    pub name: String,
    pub source: ExtractSource,
    pub pattern: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtractSource {
    ResponseHeader,
    ResponseBody,
    SetCookie,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroSub {
    pub variable: String,
    pub target: SubTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubTarget {
    Header(String),
    QueryParam(String),
    BodyParam(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Macro {
    pub id: Uuid,
    pub name: String,
    pub steps: Vec<MacroStep>,
}

pub struct MacroRunner {
    pub client: HttpClient,
}

impl MacroRunner {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn run(&self, m: &Macro) -> Result<Vec<HttpResponse>> {
        let mut state: std::collections::HashMap<String, String> = Default::default();
        let mut out = Vec::with_capacity(m.steps.len());
        for step in &m.steps {
            let mut req = step.request.clone();
            for sub in &step.substitutions {
                let Some(val) = state.get(&sub.variable) else {
                    continue;
                };
                match &sub.target {
                    SubTarget::Header(n) => req.set_header(n, val.clone()),
                    SubTarget::QueryParam(n) => {
                        req.path = inject_query(&req.path, n, val);
                    }
                    SubTarget::BodyParam(n) => {
                        if let Ok(s) = std::str::from_utf8(&req.body) {
                            req.body = bytes::Bytes::from(inject_form(s, n, val));
                        }
                    }
                }
            }
            let resp = self.client.send(&req).await?;
            for ex in &step.extracts {
                let value = match ex.source {
                    ExtractSource::ResponseHeader => resp
                        .headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case(&ex.pattern))
                        .map(|h| h.value.clone()),
                    ExtractSource::ResponseBody => {
                        let rx = Regex::new(&ex.pattern)?;
                        let body = resp.body_text().unwrap_or("");
                        rx.captures(body)
                            .and_then(|c| c.get(1).or_else(|| c.get(0)).map(|m| m.as_str().to_string()))
                    }
                    ExtractSource::SetCookie => resp
                        .headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case("Set-Cookie"))
                        .and_then(|h| {
                            h.value.split(';').next().and_then(|s| {
                                s.split_once('=').map(|(_, v)| v.trim().to_string())
                            })
                        }),
                };
                if let Some(v) = value {
                    state.insert(ex.name.clone(), v);
                }
            }
            out.push(resp);
        }
        Ok(out)
    }
}

fn inject_query(path: &str, name: &str, value: &str) -> String {
    let (base, query) = path.split_once('?').unwrap_or((path, ""));
    let mut parts: Vec<String> = query
        .split('&')
        .filter(|p| !p.is_empty() && !p.starts_with(&format!("{name}=")))
        .map(|s| s.to_string())
        .collect();
    parts.push(format!("{name}={value}"));
    format!("{base}?{}", parts.join("&"))
}

fn inject_form(body: &str, name: &str, value: &str) -> String {
    let mut parts: Vec<String> = body
        .split('&')
        .filter(|p| !p.is_empty() && !p.starts_with(&format!("{name}=")))
        .map(|s| s.to_string())
        .collect();
    parts.push(format!("{name}={value}"));
    parts.join("&")
}
