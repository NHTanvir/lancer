//! Session-handling rules: per-tool, per-URL, ordered actions.

use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwap;
use lancer_core::HttpRequest;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cookie_jar::CookieJar;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolScope {
    Proxy,
    Repeater,
    Intruder,
    Scanner,
    Sequencer,
    Extension,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionAction {
    SetHeader { name: String, value: String },
    SetCookie { name: String, value: String, domain: String, path: String },
    UseCookieJar,
    RunMacro { macro_id: Uuid },
    PromptUser { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRule {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub tools: Vec<ToolScope>,
    pub url_pattern: Option<String>,
    pub actions: Vec<SessionAction>,
}

#[derive(Default, Clone)]
pub struct SessionEngine {
    rules: Arc<ArcSwap<Vec<SessionRule>>>,
    pub jar: Arc<parking_lot::RwLock<CookieJar>>,
}

impl SessionEngine {
    pub fn new(jar: CookieJar) -> Self {
        Self {
            rules: Arc::new(ArcSwap::from_pointee(Vec::new())),
            jar: Arc::new(parking_lot::RwLock::new(jar)),
        }
    }

    pub fn replace(&self, rules: Vec<SessionRule>) {
        self.rules.store(Arc::new(rules));
    }

    pub fn rules(&self) -> Arc<Vec<SessionRule>> {
        self.rules.load_full()
    }

    /// Apply matching rules to the in-flight request before send.
    pub async fn apply(&self, tool: ToolScope, req: &mut HttpRequest) -> Result<()> {
        let rules = self.rules.load_full();
        for r in rules.iter() {
            if !r.enabled || !r.tools.contains(&tool) {
                continue;
            }
            if let Some(pat) = &r.url_pattern {
                if !req.url().contains(pat) {
                    continue;
                }
            }
            for action in &r.actions {
                match action {
                    SessionAction::SetHeader { name, value } => {
                        req.set_header(name.as_str(), value.clone());
                    }
                    SessionAction::SetCookie { name, value, .. } => {
                        let mut current = req.header("Cookie").unwrap_or("").to_string();
                        if !current.is_empty() {
                            current.push_str("; ");
                        }
                        current.push_str(&format!("{name}={value}"));
                        req.set_header("Cookie", current);
                    }
                    SessionAction::UseCookieJar => {
                        let jar = self.jar.read();
                        let cookies = jar.for_request(
                            &req.meta.host,
                            req.path.split('?').next().unwrap_or("/"),
                            req.meta.scheme == "https",
                        );
                        if !cookies.is_empty() {
                            let header = cookies
                                .iter()
                                .map(|c| format!("{}={}", c.name, c.value))
                                .collect::<Vec<_>>()
                                .join("; ");
                            req.set_header("Cookie", header);
                        }
                    }
                    SessionAction::RunMacro { .. } => {
                        // Macros are run by the host (it owns the runner);
                        // the engine just signals which one to run.
                    }
                    SessionAction::PromptUser { .. } => {
                        // Handled by the UI layer.
                    }
                }
            }
        }
        Ok(())
    }

    /// Synchronous in-flight application used by the proxy pipeline (the body of
    /// `apply` has no real awaits). Sets headers / cookies on requests whose URL
    /// matches an enabled rule scoped to `tool`.
    pub fn apply_request_sync(&self, tool: ToolScope, req: &mut HttpRequest) {
        let rules = self.rules.load_full();
        for r in rules.iter() {
            if !r.enabled || (!r.tools.is_empty() && !r.tools.contains(&tool)) {
                continue;
            }
            if let Some(pat) = &r.url_pattern {
                if !pat.is_empty() && !req.url().contains(pat) {
                    continue;
                }
            }
            for action in &r.actions {
                match action {
                    SessionAction::SetHeader { name, value } => {
                        req.set_header(name.as_str(), value.clone());
                    }
                    SessionAction::SetCookie { name, value, .. } => {
                        let mut current = req.header("Cookie").unwrap_or("").to_string();
                        if !current.is_empty() {
                            current.push_str("; ");
                        }
                        current.push_str(&format!("{name}={value}"));
                        req.set_header("Cookie", current);
                    }
                    SessionAction::UseCookieJar => {
                        let cookies = self.jar.read().for_request(
                            &req.meta.host,
                            req.path.split('?').next().unwrap_or("/"),
                            req.meta.scheme == "https",
                        );
                        if !cookies.is_empty() {
                            let header = cookies
                                .iter()
                                .map(|c| format!("{}={}", c.name, c.value))
                                .collect::<Vec<_>>()
                                .join("; ");
                            req.set_header("Cookie", header);
                        }
                    }
                    SessionAction::RunMacro { .. } | SessionAction::PromptUser { .. } => {}
                }
            }
        }
    }
}
