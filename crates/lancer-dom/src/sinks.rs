//! Source/sink trace for DOM XSS.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomSource {
    LocationHash,
    LocationSearch,
    LocationHref,
    LocationPathname,
    DocumentReferrer,
    DocumentCookie,
    PostMessage,
    LocalStorage,
    SessionStorage,
    IndexedDb,
    UrlSearchParams,
    History,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomSink {
    InnerHtml,
    OuterHtml,
    DocumentWrite,
    Eval,
    NewFunction,
    SetTimeoutString,
    SetIntervalString,
    InsertAdjacentHtml,
    LocationAssign,
    ScriptSrc,
    AnchorHref,
    IframeSrc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomFinding {
    pub source: DomSource,
    pub sink: DomSink,
    pub line: usize,
    pub snippet: String,
    pub note: String,
}

static SOURCE_PATTERNS: Lazy<Vec<(DomSource, Regex)>> = Lazy::new(|| {
    vec![
        (DomSource::LocationHash, Regex::new(r"\blocation\.hash\b").unwrap()),
        (DomSource::LocationSearch, Regex::new(r"\blocation\.search\b").unwrap()),
        (DomSource::LocationHref, Regex::new(r"\blocation\.href\b").unwrap()),
        (DomSource::LocationPathname, Regex::new(r"\blocation\.pathname\b").unwrap()),
        (DomSource::DocumentReferrer, Regex::new(r"\bdocument\.referrer\b").unwrap()),
        (DomSource::DocumentCookie, Regex::new(r"\bdocument\.cookie\b").unwrap()),
        (DomSource::LocalStorage, Regex::new(r"\blocalStorage\.").unwrap()),
        (DomSource::SessionStorage, Regex::new(r"\bsessionStorage\.").unwrap()),
        (DomSource::IndexedDb, Regex::new(r"\bindexedDB\.").unwrap()),
        (DomSource::UrlSearchParams, Regex::new(r"\bnew URLSearchParams\(").unwrap()),
        (DomSource::History, Regex::new(r"\bhistory\.(state|pushState)\b").unwrap()),
        (DomSource::PostMessage, Regex::new(r"\b\.data\b").unwrap()),
    ]
});

static SINK_PATTERNS: Lazy<Vec<(DomSink, Regex)>> = Lazy::new(|| {
    vec![
        (DomSink::InnerHtml, Regex::new(r"\.innerHTML\s*=").unwrap()),
        (DomSink::OuterHtml, Regex::new(r"\.outerHTML\s*=").unwrap()),
        (DomSink::DocumentWrite, Regex::new(r"\bdocument\.write(?:ln)?\s*\(").unwrap()),
        (DomSink::Eval, Regex::new(r"\beval\s*\(").unwrap()),
        (DomSink::NewFunction, Regex::new(r"\bnew Function\s*\(").unwrap()),
        (DomSink::SetTimeoutString, Regex::new(r#"\bsetTimeout\s*\(\s*['"]"#).unwrap()),
        (DomSink::SetIntervalString, Regex::new(r#"\bsetInterval\s*\(\s*['"]"#).unwrap()),
        (DomSink::InsertAdjacentHtml, Regex::new(r"\.insertAdjacentHTML\s*\(").unwrap()),
        (DomSink::LocationAssign, Regex::new(r"\blocation\s*=\s*").unwrap()),
        (DomSink::ScriptSrc, Regex::new(r"\.src\s*=\s*").unwrap()),
        (DomSink::AnchorHref, Regex::new(r"\.href\s*=\s*").unwrap()),
        (DomSink::IframeSrc, Regex::new(r"<iframe[^>]*src\s*=").unwrap()),
    ]
});

pub fn analyze_js(body: &str) -> Vec<DomFinding> {
    let mut hits = Vec::new();
    for (line_idx, line) in body.lines().enumerate() {
        for (sink, sink_rx) in SINK_PATTERNS.iter() {
            if !sink_rx.is_match(line) {
                continue;
            }
            for (source, source_rx) in SOURCE_PATTERNS.iter() {
                if source_rx.is_match(line) {
                    hits.push(DomFinding {
                        source: *source,
                        sink: *sink,
                        line: line_idx + 1,
                        snippet: line.trim().to_string(),
                        note: format!("{:?} → {:?} on a single line", source, sink),
                    });
                }
            }
        }
    }
    hits
}
