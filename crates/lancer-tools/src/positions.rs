//! Payload-position parsing.
//!
//! A request template carries payload positions marked with `§…§` (Burp's
//! convention). Sniper iterates one position at a time; Battering Ram fires the
//! same payload to all positions at once; Pitchfork/Cluster Bomb pair multiple
//! sets across positions.

use lancer_core::HttpRequest;
use serde::{Deserialize, Serialize};

/// Default marker, identical to Burp's. Configurable per-attack.
pub const DEFAULT_MARKER: char = '§';

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PositionSlot {
    Path,
    Body,
    Header(usize), // index of header in the request
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Position {
    pub slot: PositionSlot,
    pub start: usize,
    pub end: usize,
    /// Original text between the markers (default payload).
    pub original: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedTemplate {
    pub request: HttpRequest,
    pub positions: Vec<Position>,
    pub marker: char,
}

impl ParsedTemplate {
    /// Parse a request whose path / body / header values contain `§…§` markers.
    pub fn parse(mut req: HttpRequest, marker: char) -> Self {
        let mut positions = Vec::new();
        if let Some(new_path) = scan_and_replace(&req.path, marker, |start, end, original| {
            positions.push(Position {
                slot: PositionSlot::Path,
                start,
                end,
                original,
            });
        }) {
            req.path = new_path;
        }
        if let Ok(body_str) = std::str::from_utf8(&req.body) {
            if let Some(new_body) = scan_and_replace(body_str, marker, |start, end, original| {
                positions.push(Position {
                    slot: PositionSlot::Body,
                    start,
                    end,
                    original,
                });
            }) {
                req.body = bytes::Bytes::from(new_body);
            }
        }
        for (idx, h) in req.headers.iter_mut().enumerate() {
            if let Some(new_v) = scan_and_replace(&h.value, marker, |start, end, original| {
                positions.push(Position {
                    slot: PositionSlot::Header(idx),
                    start,
                    end,
                    original,
                });
            }) {
                h.value = new_v;
            }
        }
        Self { request: req, positions, marker }
    }

    /// Render a concrete request by substituting payloads for each position.
    /// `payloads.len()` must equal `positions.len()`. Empty string = leave-as-original.
    pub fn render(&self, payloads: &[String]) -> HttpRequest {
        assert_eq!(payloads.len(), self.positions.len());
        let mut out = self.request.clone();
        // We must apply substitutions from highest offset to lowest to avoid
        // shifting later spans.
        let mut sorted: Vec<_> = self
            .positions
            .iter()
            .enumerate()
            .collect();
        sorted.sort_by_key(|(_, p)| std::cmp::Reverse((p.slot, p.start)));
        // Group by slot since spans are per-slot.
        for (i, pos) in sorted {
            let p = &payloads[i];
            match pos.slot {
                PositionSlot::Path => {
                    splice_in_place(&mut out.path, pos.start, pos.end, p);
                }
                PositionSlot::Body => {
                    let mut s = String::from_utf8_lossy(&out.body).into_owned();
                    splice_in_place(&mut s, pos.start, pos.end, p);
                    out.body = bytes::Bytes::from(s);
                }
                PositionSlot::Header(idx) => {
                    if let Some(h) = out.headers.get_mut(idx) {
                        splice_in_place(&mut h.value, pos.start, pos.end, p);
                    }
                }
            }
        }
        out.meta.id = uuid::Uuid::new_v4();
        out.meta.tool_generated = true;
        out
    }

    pub fn position_count(&self) -> usize {
        self.positions.len()
    }
}

fn splice_in_place(haystack: &mut String, start: usize, end: usize, replacement: &str) {
    if start > haystack.len() || end > haystack.len() || start > end {
        return;
    }
    haystack.replace_range(start..end, replacement);
}

/// Scan `input` for paired markers, return the cleaned string (with markers
/// stripped) and call `record` for each pair found. Returns `None` if no
/// markers were present.
fn scan_and_replace<F: FnMut(usize, usize, String)>(
    input: &str,
    marker: char,
    mut record: F,
) -> Option<String> {
    if !input.contains(marker) {
        return None;
    }
    let mut out = String::with_capacity(input.len());
    let mut chars = input.char_indices().peekable();
    let mut open: Option<usize> = None;
    let mut last_idx = 0;
    while let Some((i, c)) = chars.next() {
        if c == marker {
            match open {
                None => {
                    out.push_str(&input[last_idx..i]);
                    open = Some(out.len());
                    last_idx = i + c.len_utf8();
                }
                Some(start) => {
                    let payload_text = &input[last_idx..i];
                    out.push_str(payload_text);
                    let end = out.len();
                    record(start, end, payload_text.to_string());
                    last_idx = i + c.len_utf8();
                    open = None;
                }
            }
        }
    }
    out.push_str(&input[last_idx..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lancer_core::HttpRequest;

    #[test]
    fn parse_path() {
        let mut r = HttpRequest::builder("GET", "https://x.com/users/§1§/edit").unwrap();
        r.set_header("X-Test", "value-§a§-here");
        let t = ParsedTemplate::parse(r, DEFAULT_MARKER);
        assert_eq!(t.positions.len(), 2);
        let rendered = t.render(&["42".into(), "z".into()]);
        assert_eq!(rendered.path, "/users/42/edit");
        assert_eq!(rendered.header("X-Test"), Some("value-z-here"));
    }
}
