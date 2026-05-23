//! Command palette — Ctrl+K / Cmd+K fuzzy actions.

use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandSource {
    Builtin,
    Plugin,
    History,
    Bambda,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub id: String,
    pub label: String,
    pub keywords: Vec<String>,
    pub hotkey: Option<String>,
    pub source: CommandSource,
}

#[derive(Default, Clone)]
pub struct CommandPalette {
    items: Arc<RwLock<Vec<Command>>>,
}

impl CommandPalette {
    pub fn new() -> Self {
        let p = Self::default();
        for c in builtin() {
            p.register(c);
        }
        p
    }

    pub fn register(&self, cmd: Command) {
        let mut items = self.items.write();
        items.retain(|c| c.id != cmd.id);
        items.push(cmd);
    }

    pub fn unregister(&self, id: &str) {
        self.items.write().retain(|c| c.id != id);
    }

    /// Naive fuzzy match: items whose label or keywords contain every
    /// space-separated token in `query`, case-insensitive.
    pub fn search(&self, query: &str) -> Vec<Command> {
        let q = query.to_ascii_lowercase();
        let tokens: Vec<&str> = q.split_whitespace().collect();
        let items = self.items.read();
        let mut scored: Vec<(usize, Command)> = items
            .iter()
            .filter_map(|c| {
                let hay = format!(
                    "{} {}",
                    c.label.to_ascii_lowercase(),
                    c.keywords.join(" ").to_ascii_lowercase()
                );
                if tokens.iter().all(|t| hay.contains(t)) {
                    Some((c.label.len(), c.clone()))
                } else {
                    None
                }
            })
            .collect();
        scored.sort_by_key(|(len, _)| *len);
        scored.into_iter().map(|(_, c)| c).take(50).collect()
    }
}

fn builtin() -> Vec<Command> {
    let make = |id: &str, label: &str, keys: &[&str], hot: Option<&str>| Command {
        id: id.to_string(),
        label: label.to_string(),
        keywords: keys.iter().map(|s| s.to_string()).collect(),
        hotkey: hot.map(|s| s.to_string()),
        source: CommandSource::Builtin,
    };
    vec![
        make("proxy.toggle_intercept", "Proxy: toggle interception", &["intercept", "pause"], Some("Ctrl+Shift+I")),
        make("proxy.open_browser", "Proxy: open built-in browser", &["browser", "chromium"], None),
        make("repeater.new", "Repeater: new tab", &["repeater", "tab"], Some("Ctrl+R")),
        make("repeater.send", "Repeater: send current tab", &["send"], Some("Ctrl+Enter")),
        make("intruder.new", "Intruder: new attack", &["intruder"], None),
        make("scanner.run", "Scanner: run on selection", &["scan", "audit"], None),
        make("project.save", "Project: save", &["save"], Some("Ctrl+S")),
        make("project.open", "Project: open", &["open", "load"], Some("Ctrl+O")),
        make("history.search", "History: search", &["history", "find"], Some("Ctrl+F")),
        make("decoder.smart", "Decoder: smart-decode selection", &["decode"], None),
        make("ui.theme.dark", "UI: dark theme", &["theme", "dark"], None),
        make("ui.theme.light", "UI: light theme", &["theme", "light"], None),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzzy_search() {
        let p = CommandPalette::new();
        let hits = p.search("intercept");
        assert!(hits.iter().any(|c| c.id == "proxy.toggle_intercept"));
    }
}
