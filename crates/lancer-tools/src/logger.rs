//! Logger — every HTTP message that flows through Lancer (proxy, repeater,
//! intruder, scanner) is funneled into here.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use lancer_core::{HttpRequest, HttpResponse};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    Proxy,
    Repeater,
    Intruder,
    Scanner,
    Extension,
    SessionHandler,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: Uuid,
    pub captured_at: DateTime<Utc>,
    pub source: Source,
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub note: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct LogFilter {
    pub source: Option<Source>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub status_min: Option<u16>,
    pub status_max: Option<u16>,
    pub bambda: Option<String>,
}

impl LogFilter {
    fn passes(&self, entry: &LogEntry) -> bool {
        if let Some(s) = self.source {
            if entry.source != s {
                return false;
            }
        }
        if let Some(h) = &self.host {
            if !entry.request.meta.host.contains(h) {
                return false;
            }
        }
        if let Some(m) = &self.method {
            if !entry.request.method.as_str().eq_ignore_ascii_case(m) {
                return false;
            }
        }
        if let (Some(min), Some(resp)) = (self.status_min, &entry.response) {
            if resp.status < min {
                return false;
            }
        }
        if let (Some(max), Some(resp)) = (self.status_max, &entry.response) {
            if resp.status > max {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Default)]
pub struct Logger {
    entries: Arc<RwLock<Vec<LogEntry>>>,
    capture: Arc<RwLock<LogFilter>>,
    max_entries: usize,
}

impl Logger {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
            capture: Arc::new(RwLock::new(LogFilter::default())),
            max_entries,
        }
    }

    pub fn record(&self, source: Source, req: HttpRequest, resp: Option<HttpResponse>) {
        let entry = LogEntry {
            id: Uuid::new_v4(),
            captured_at: Utc::now(),
            source,
            request: req,
            response: resp,
            note: None,
        };
        if !self.capture.read().passes(&entry) {
            return;
        }
        let mut e = self.entries.write();
        e.push(entry);
        if self.max_entries > 0 && e.len() > self.max_entries {
            let drop = e.len() - self.max_entries;
            e.drain(0..drop);
        }
    }

    pub fn list(&self, view: &LogFilter) -> Vec<LogEntry> {
        self.entries
            .read()
            .iter()
            .filter(|e| view.passes(e))
            .cloned()
            .collect()
    }

    pub fn clear(&self) {
        self.entries.write().clear();
    }

    pub fn set_capture_filter(&self, f: LogFilter) {
        *self.capture.write() = f;
    }
}
