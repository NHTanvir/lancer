//! Server-Sent Events (text/event-stream) support.
//!
//! For an SSE response we don't buffer the body — we forward chunks straight
//! to the client and emit one event per `\n\n`-delimited record so the History
//! pane can show a streaming view.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SseEvent {
    pub id: Option<String>,
    pub event: Option<String>,
    pub data: String,
    pub retry: Option<u64>,
}

/// Parse one or more events out of an `event-stream` text buffer. Returns
/// the leftover (incomplete tail) along with the parsed events.
pub fn parse_chunk(input: &str) -> (Vec<SseEvent>, String) {
    let mut events = Vec::new();
    let mut cur = SseEvent::default();
    let bytes = input.as_bytes();

    let mut line_start = 0;
    let mut last_blank = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            let line = std::str::from_utf8(&bytes[line_start..i]).unwrap_or("").trim_end_matches('\r');
            if line.is_empty() {
                if !cur.data.is_empty() || cur.id.is_some() || cur.event.is_some() {
                    events.push(std::mem::take(&mut cur));
                }
                last_blank = i + 1;
            } else if let Some(value) = line.strip_prefix("data:") {
                if !cur.data.is_empty() {
                    cur.data.push('\n');
                }
                cur.data.push_str(value.trim_start());
            } else if let Some(value) = line.strip_prefix("event:") {
                cur.event = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("id:") {
                cur.id = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("retry:") {
                cur.retry = value.trim().parse().ok();
            }
            line_start = i + 1;
        }
        i += 1;
    }
    let tail_start = last_blank;
    let tail = std::str::from_utf8(&bytes[tail_start..]).unwrap_or("").to_string();
    (events, tail)
}

pub fn is_event_stream(content_type: &str) -> bool {
    content_type.trim().to_lowercase().starts_with("text/event-stream")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multi_line() {
        let s = "data: hello\ndata: world\n\ndata: ping\n\nid: 7\ndata: tail";
        let (events, tail) = parse_chunk(s);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, "hello\nworld");
        assert_eq!(events[1].data, "ping");
        assert!(tail.contains("tail"));
    }
}
