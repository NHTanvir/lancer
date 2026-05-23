//! Parsed view of an HTTP request — used by the Inspector pane and by the
//! Intruder / Scanner to decide where insertion points live.

use serde::{Deserialize, Serialize};

use crate::http_msg::{HttpRequest, HttpResponse, MimeKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParamLocation {
    Url,
    Body,
    Cookie,
    Header,
    JsonKey,
    JsonValue,
    XmlAttr,
    XmlText,
    Path,
    Multipart,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    pub value: String,
    pub location: ParamLocation,
    /// Byte offsets within the message body / URL for in-place editing &
    /// payload-position generation.
    pub span: Option<(usize, usize)>,
}

impl Param {
    pub fn new(
        name: impl Into<String>,
        value: impl Into<String>,
        location: ParamLocation,
    ) -> Self {
        Self { name: name.into(), value: value.into(), location, span: None }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Inspector {
    pub params: Vec<Param>,
}

impl Inspector {
    /// Build a parsed view of a request. Pure function over the bytes.
    pub fn from_request(req: &HttpRequest) -> Self {
        let mut params = Vec::new();
        parse_url_params(&req.path, &mut params);
        for h in &req.headers {
            if h.name.eq_ignore_ascii_case("Cookie") {
                parse_cookie(&h.value, &mut params);
            } else {
                params.push(Param::new(&h.name, &h.value, ParamLocation::Header));
            }
        }
        let ct = req
            .header("Content-Type")
            .map(MimeKind::from_content_type)
            .unwrap_or(MimeKind::Unknown);
        match ct {
            MimeKind::FormUrlEncoded => {
                if let Some(body) = req.body_text() {
                    parse_form_urlencoded(body, &mut params);
                }
            }
            MimeKind::Json => {
                if let Some(body) = req.body_text() {
                    if let Ok(v) = serde_json::from_str(body) {
                        walk_json(&v, "", &mut params);
                    }
                }
            }
            MimeKind::Multipart => {
                if let Some(body) = req.body_text() {
                    let boundary = req
                        .header("Content-Type")
                        .and_then(|c| extract_boundary(c));
                    if let Some(b) = boundary {
                        parse_multipart(body, &b, &mut params);
                    }
                }
            }
            _ => {}
        }
        Self { params }
    }

    pub fn from_response(resp: &HttpResponse) -> Self {
        let mut params = Vec::new();
        for h in &resp.headers {
            if h.name.eq_ignore_ascii_case("Set-Cookie") {
                parse_set_cookie(&h.value, &mut params);
            } else {
                params.push(Param::new(&h.name, &h.value, ParamLocation::Header));
            }
        }
        Self { params }
    }

    pub fn find(&self, name: &str) -> Option<&Param> {
        self.params.iter().find(|p| p.name.eq_ignore_ascii_case(name))
    }

    pub fn by_location(&self, loc: ParamLocation) -> impl Iterator<Item = &Param> {
        self.params.iter().filter(move |p| p.location == loc)
    }
}

fn parse_url_params(path: &str, out: &mut Vec<Param>) {
    if let Some((_, query)) = path.split_once('?') {
        parse_form_urlencoded(query, out);
        for p in out.iter_mut() {
            if matches!(p.location, ParamLocation::Body) {
                p.location = ParamLocation::Url;
            }
        }
    }
}

fn parse_form_urlencoded(s: &str, out: &mut Vec<Param>) {
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = decode_percent(k);
        let v = decode_percent(v);
        out.push(Param::new(k, v, ParamLocation::Body));
    }
}

fn decode_percent(s: &str) -> String {
    percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn parse_cookie(value: &str, out: &mut Vec<Param>) {
    for pair in value.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.push(Param::new(k, v, ParamLocation::Cookie));
    }
}

fn parse_set_cookie(value: &str, out: &mut Vec<Param>) {
    if let Some(first) = value.split(';').next() {
        let (k, v) = first.split_once('=').unwrap_or((first, ""));
        out.push(Param::new(k.trim(), v.trim(), ParamLocation::Cookie));
    }
}

fn walk_json(v: &serde_json::Value, path: &str, out: &mut Vec<Param>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, vv) in map {
                let next = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                out.push(Param::new(&next, "", ParamLocation::JsonKey));
                walk_json(vv, &next, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, vv) in arr.iter().enumerate() {
                let next = format!("{path}[{i}]");
                walk_json(vv, &next, out);
            }
        }
        serde_json::Value::String(s) => {
            out.push(Param::new(path, s, ParamLocation::JsonValue));
        }
        serde_json::Value::Number(n) => {
            out.push(Param::new(path, n.to_string(), ParamLocation::JsonValue));
        }
        serde_json::Value::Bool(b) => {
            out.push(Param::new(path, b.to_string(), ParamLocation::JsonValue));
        }
        serde_json::Value::Null => {
            out.push(Param::new(path, "null", ParamLocation::JsonValue));
        }
    }
}

fn extract_boundary(ct: &str) -> Option<String> {
    for piece in ct.split(';') {
        let piece = piece.trim();
        if let Some(rest) = piece.strip_prefix("boundary=") {
            return Some(rest.trim_matches('"').to_string());
        }
    }
    None
}

fn parse_multipart(body: &str, boundary: &str, out: &mut Vec<Param>) {
    let sep = format!("--{boundary}");
    for part in body.split(&sep[..]) {
        let part = part.trim_start_matches('\r').trim_start_matches('\n');
        if part.is_empty() || part.starts_with("--") {
            continue;
        }
        let (headers, value) = match part.find("\r\n\r\n") {
            Some(i) => (&part[..i], &part[i + 4..]),
            None => continue,
        };
        let mut name = None;
        for line in headers.split("\r\n") {
            if let Some(rest) = line.strip_prefix("Content-Disposition:") {
                if let Some(i) = rest.find("name=") {
                    let after = &rest[i + 5..];
                    let n: String = after
                        .trim_matches('"')
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim_matches('"')
                        .to_string();
                    name = Some(n);
                }
            }
        }
        if let Some(name) = name {
            out.push(Param::new(name, value.trim_end(), ParamLocation::Multipart));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_msg::HttpRequest;

    #[test]
    fn url_params() {
        let req = HttpRequest::builder("GET", "https://x.com/p?a=1&b=hello%20world").unwrap();
        let insp = Inspector::from_request(&req);
        let a = insp.find("a").unwrap();
        assert_eq!(a.value, "1");
        assert_eq!(a.location, ParamLocation::Url);
        let b = insp.find("b").unwrap();
        assert_eq!(b.value, "hello world");
    }

    #[test]
    fn json_walk() {
        let mut req = HttpRequest::builder("POST", "https://x.com/p").unwrap();
        req.set_header("Content-Type", "application/json");
        req.body = bytes::Bytes::from_static(b"{\"a\":1,\"b\":{\"c\":\"x\"}}");
        let insp = Inspector::from_request(&req);
        assert!(insp.params.iter().any(|p| p.name == "b.c" && p.value == "x"));
    }
}
