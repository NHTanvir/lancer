//! Encode/decode/hash transforms shared by Decoder, Intruder payload processing,
//! and Bambda helpers.

use std::io::Read;

use base64::{engine::general_purpose, Engine as _};
use flate2::read::{GzDecoder, GzEncoder};
use flate2::Compression;
use md5::{Digest as _, Md5};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformOp {
    UrlEncode,
    UrlDecode,
    HtmlEncode,
    HtmlDecode,
    Base64Encode,
    Base64Decode,
    HexEncode,
    HexDecode,
    AsciiHexEncode,
    AsciiHexDecode,
    OctalEncode,
    OctalDecode,
    BinaryEncode,
    BinaryDecode,
    GzipEncode,
    GzipDecode,
    Md2,
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    ToUpper,
    ToLower,
}

impl TransformOp {
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "url-encode" | "urlencode" | "url" => TransformOp::UrlEncode,
            "url-decode" | "urldecode" => TransformOp::UrlDecode,
            "html-encode" | "htmlencode" | "html" => TransformOp::HtmlEncode,
            "html-decode" | "htmldecode" => TransformOp::HtmlDecode,
            "base64-encode" | "base64" | "b64" => TransformOp::Base64Encode,
            "base64-decode" | "b64-decode" => TransformOp::Base64Decode,
            "hex-encode" | "hex" => TransformOp::HexEncode,
            "hex-decode" => TransformOp::HexDecode,
            "ascii-hex-encode" => TransformOp::AsciiHexEncode,
            "ascii-hex-decode" => TransformOp::AsciiHexDecode,
            "octal-encode" => TransformOp::OctalEncode,
            "octal-decode" => TransformOp::OctalDecode,
            "binary-encode" => TransformOp::BinaryEncode,
            "binary-decode" => TransformOp::BinaryDecode,
            "gzip" | "gzip-encode" => TransformOp::GzipEncode,
            "gunzip" | "gzip-decode" => TransformOp::GzipDecode,
            "md2" => TransformOp::Md2,
            "md5" => TransformOp::Md5,
            "sha1" => TransformOp::Sha1,
            "sha256" => TransformOp::Sha256,
            "sha384" => TransformOp::Sha384,
            "sha512" => TransformOp::Sha512,
            "sha3-224" => TransformOp::Sha3_224,
            "sha3-256" => TransformOp::Sha3_256,
            "sha3-384" => TransformOp::Sha3_384,
            "sha3-512" => TransformOp::Sha3_512,
            "upper" | "toupper" => TransformOp::ToUpper,
            "lower" | "tolower" => TransformOp::ToLower,
            _ => return None,
        })
    }

    pub fn apply(&self, input: &[u8]) -> Result<Vec<u8>> {
        Ok(match self {
            TransformOp::UrlEncode => url_encode(input),
            TransformOp::UrlDecode => url_decode(input)?,
            TransformOp::HtmlEncode => html_encode(input),
            TransformOp::HtmlDecode => html_decode(input),
            TransformOp::Base64Encode => general_purpose::STANDARD.encode(input).into_bytes(),
            TransformOp::Base64Decode => general_purpose::STANDARD
                .decode(input)
                .map_err(|e| Error::parse(format!("base64: {e}")))?,
            TransformOp::HexEncode => hex::encode(input).into_bytes(),
            TransformOp::HexDecode => hex::decode(input)
                .map_err(|e| Error::parse(format!("hex: {e}")))?,
            TransformOp::AsciiHexEncode => input
                .iter()
                .map(|b| format!("\\x{:02x}", b))
                .collect::<String>()
                .into_bytes(),
            TransformOp::AsciiHexDecode => ascii_hex_decode(std::str::from_utf8(input)?)?,
            TransformOp::OctalEncode => input
                .iter()
                .map(|b| format!("\\{:03o}", b))
                .collect::<String>()
                .into_bytes(),
            TransformOp::OctalDecode => octal_decode(std::str::from_utf8(input)?)?,
            TransformOp::BinaryEncode => input
                .iter()
                .map(|b| format!("{:08b}", b))
                .collect::<String>()
                .into_bytes(),
            TransformOp::BinaryDecode => binary_decode(std::str::from_utf8(input)?)?,
            TransformOp::GzipEncode => gzip_encode(input)?,
            TransformOp::GzipDecode => gzip_decode(input)?,
            TransformOp::Md2 => md2_hash(input),
            TransformOp::Md5 => Md5::digest(input).to_vec(),
            TransformOp::Sha1 => Sha1::digest(input).to_vec(),
            TransformOp::Sha256 => Sha256::digest(input).to_vec(),
            TransformOp::Sha384 => Sha384::digest(input).to_vec(),
            TransformOp::Sha512 => Sha512::digest(input).to_vec(),
            TransformOp::Sha3_224 => sha3::Sha3_224::digest(input).to_vec(),
            TransformOp::Sha3_256 => sha3::Sha3_256::digest(input).to_vec(),
            TransformOp::Sha3_384 => sha3::Sha3_384::digest(input).to_vec(),
            TransformOp::Sha3_512 => sha3::Sha3_512::digest(input).to_vec(),
            TransformOp::ToUpper => std::str::from_utf8(input)?.to_ascii_uppercase().into_bytes(),
            TransformOp::ToLower => std::str::from_utf8(input)?.to_ascii_lowercase().into_bytes(),
        })
    }
}

fn url_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3);
    for &b in input {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b),
            _ => {
                out.push(b'%');
                out.extend_from_slice(format!("{:02X}", b).as_bytes());
            }
        }
    }
    out
}

fn url_decode(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < input.len() => {
                let hi = (input[i + 1] as char).to_digit(16);
                let lo = (input[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => return Err(Error::parse("bad % escape")),
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(out)
}

fn html_encode(input: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(input);
    let mut out = String::with_capacity(input.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out.into_bytes()
}

fn html_decode(input: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(input);
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '&' {
            let mut buf = String::new();
            while let Some(&nc) = chars.peek() {
                chars.next();
                if nc == ';' {
                    break;
                }
                buf.push(nc);
                if buf.len() > 8 {
                    break;
                }
            }
            let replacement = match buf.as_str() {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "#39" => Some('\''),
                s if s.starts_with("#x") => {
                    u32::from_str_radix(&s[2..], 16).ok().and_then(char::from_u32)
                }
                s if s.starts_with('#') => {
                    s[1..].parse::<u32>().ok().and_then(char::from_u32)
                }
                _ => None,
            };
            match replacement {
                Some(r) => out.push(r),
                None => {
                    out.push('&');
                    out.push_str(&buf);
                }
            }
        } else {
            out.push(c);
        }
    }
    out.into_bytes()
}

fn ascii_hex_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() && bytes[i + 1] == b'x' {
            let h =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 2..i + 4])?, 16)
                    .map_err(|e| Error::parse(format!("\\x: {e}")))?;
            out.push(h);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn octal_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let v = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 4])?, 8)
                .map_err(|e| Error::parse(format!("octal: {e}")))?;
            out.push(v);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn binary_decode(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| *c == '0' || *c == '1').collect();
    if cleaned.len() % 8 != 0 {
        return Err(Error::parse("binary length must be multiple of 8"));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 8);
    for chunk in cleaned.as_bytes().chunks(8) {
        let v = u8::from_str_radix(std::str::from_utf8(chunk)?, 2)
            .map_err(|e| Error::parse(format!("binary: {e}")))?;
        out.push(v);
    }
    Ok(out)
}

fn gzip_encode(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut enc = GzEncoder::new(input, Compression::default());
    enc.read_to_end(&mut out).map_err(Error::Io)?;
    Ok(out)
}

fn gzip_decode(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut dec = GzDecoder::new(input);
    dec.read_to_end(&mut out).map_err(Error::Io)?;
    Ok(out)
}

fn md2_hash(input: &[u8]) -> Vec<u8> {
    use md2::Md2;
    Md2::digest(input).to_vec()
}

/// Apply an ordered chain of transforms.
pub fn chain(ops: &[TransformOp], input: &[u8]) -> Result<Vec<u8>> {
    let mut buf = input.to_vec();
    for op in ops {
        buf = op.apply(&buf)?;
    }
    Ok(buf)
}

/// Smart-decode: try to strip layered URL / Base64 / hex / gzip / html escapes
/// repeatedly until no further decoding is possible.
pub fn smart_decode(input: &[u8]) -> Vec<u8> {
    let mut current = input.to_vec();
    loop {
        let next = smart_decode_once(&current);
        match next {
            Some(n) if n != current && !n.is_empty() => current = n,
            _ => return current,
        }
    }
}

fn smart_decode_once(input: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(input).ok()?;
    if s.starts_with('%') || s.contains('%') {
        if let Ok(v) = url_decode(input) {
            if v != input {
                return Some(v);
            }
        }
    }
    if s.contains("&amp;") || s.contains("&lt;") || s.contains("&gt;") || s.contains("&#") {
        let v = html_decode(input);
        if v != input {
            return Some(v);
        }
    }
    if s.chars().all(|c| c.is_ascii_hexdigit()) && s.len() % 2 == 0 && !s.is_empty() {
        if let Ok(v) = hex::decode(s) {
            return Some(v);
        }
    }
    if !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
        })
        && s.len() % 4 == 0
    {
        if let Ok(v) = general_purpose::STANDARD.decode(s) {
            if !v.is_empty() && v.iter().any(|b| *b != 0) {
                return Some(v);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_roundtrip() {
        let s = b"hello world+&";
        let encoded = TransformOp::UrlEncode.apply(s).unwrap();
        let decoded = TransformOp::UrlDecode.apply(&encoded).unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn base64_roundtrip() {
        let s = b"the quick brown fox";
        let e = TransformOp::Base64Encode.apply(s).unwrap();
        let d = TransformOp::Base64Decode.apply(&e).unwrap();
        assert_eq!(d, s);
    }

    #[test]
    fn smart_layered() {
        // double URL-encoded then base64'd
        let inner = "hello world";
        let url = url_encode(inner.as_bytes());
        let url_str = String::from_utf8(url).unwrap();
        let b64 = general_purpose::STANDARD.encode(url_str.as_bytes());
        let out = smart_decode(b64.as_bytes());
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn html_roundtrip() {
        let v = b"<b>&\"hi";
        let e = TransformOp::HtmlEncode.apply(v).unwrap();
        let d = TransformOp::HtmlDecode.apply(&e).unwrap();
        assert_eq!(d, v);
    }
}
