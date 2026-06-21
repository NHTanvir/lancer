//! postMessage flow logger: finds every `window.addEventListener("message", …)`
//! handler and every `*.postMessage(…)` call site in captured JS.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointKind {
    Listener,
    Sender,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMessageEndpoint {
    pub kind: EndpointKind,
    pub line: usize,
    pub snippet: String,
    /// Whether the endpoint passes "*" as the target origin (insecure).
    pub wildcard_origin: bool,
    /// Whether the handler appears to inspect `event.origin` before acting.
    pub origin_validated: bool,
}

static LISTENER_RX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"addEventListener\s*\(\s*['"]message['"]\s*,"#).unwrap()
});
static SENDER_RX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.postMessage\s*\(").unwrap());
static WILDCARD_RX: Lazy<Regex> = Lazy::new(|| Regex::new(r#"['"]\*['"]"#).unwrap());

pub fn find_message_endpoints(body: &str) -> Vec<PostMessageEndpoint> {
    let mut out = Vec::new();
    let mut listener_buffer: Option<(usize, String)> = None;

    // Emit a buffered listener, computing origin-validation over up to 9 lines
    // starting at its 1-based line number.
    let emit_listener = |out: &mut Vec<PostMessageEndpoint>, l: usize, snip: String| {
        let block = body
            .lines()
            .skip(l - 1)
            .take(9)
            .collect::<Vec<_>>()
            .join("\n");
        let validated = block.contains("event.origin") || block.contains(".origin ==");
        out.push(PostMessageEndpoint {
            kind: EndpointKind::Listener,
            line: l,
            snippet: snip,
            wildcard_origin: false,
            origin_validated: validated,
        });
    };

    for (line_idx, line) in body.lines().enumerate() {
        if LISTENER_RX.is_match(line) {
            // Flush any still-pending listener before overwriting the slot,
            // otherwise closely-spaced listeners would be silently dropped.
            if let Some((l, snip)) = listener_buffer.take() {
                emit_listener(&mut out, l, snip);
            }
            listener_buffer = Some((line_idx + 1, line.trim().to_string()));
        }
        if SENDER_RX.is_match(line) {
            out.push(PostMessageEndpoint {
                kind: EndpointKind::Sender,
                line: line_idx + 1,
                snippet: line.trim().to_string(),
                wildcard_origin: WILDCARD_RX.is_match(line),
                origin_validated: false,
            });
        }
        if let Some((l, _)) = listener_buffer {
            // Look at the next ~8 lines for origin validation.
            if line_idx + 1 == l + 8 {
                let (l, snip) = listener_buffer.take().unwrap();
                emit_listener(&mut out, l, snip);
            }
        }
    }
    // flush remaining listener if file ended before lookahead
    if let Some((l, snip)) = listener_buffer.take() {
        emit_listener(&mut out, l, snip);
    }
    out
}
