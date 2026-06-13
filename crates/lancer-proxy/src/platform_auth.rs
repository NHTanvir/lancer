//! Platform authentication: Basic, Digest, and a Negotiate/NTLM hook.
//!
//! When the upstream responds 401 with a WWW-Authenticate challenge that
//! matches a configured credential, Lancer re-issues the request with the
//! correct Authorization header.

use base64::{engine::general_purpose, Engine as _};
use md5::{Digest as _, Md5};
use rand::Rng;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthScheme {
    Basic,
    Digest,
    Ntlm,
    Negotiate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCredential {
    pub host_pattern: String,
    pub scheme: AuthScheme,
    pub username: String,
    pub password: String,
    pub domain: Option<String>,
}

impl AuthCredential {
    pub fn matches(&self, host: &str) -> bool {
        if let Some(rest) = self.host_pattern.strip_prefix("*.") {
            host == rest || host.ends_with(&format!(".{rest}"))
        } else {
            host.eq_ignore_ascii_case(&self.host_pattern)
        }
    }
}

/// Produce an `Authorization` header value given a 401 challenge.
/// Returns `None` if we can't satisfy the challenge.
pub fn answer_challenge(
    challenge: &str,
    cred: &AuthCredential,
    method: &str,
    uri: &str,
) -> Option<String> {
    let scheme_lower = challenge.split_whitespace().next()?.to_lowercase();
    match scheme_lower.as_str() {
        "basic" if cred.scheme == AuthScheme::Basic => Some(basic(&cred.username, &cred.password)),
        "digest" if cred.scheme == AuthScheme::Digest => digest(challenge, cred, method, uri),
        "ntlm" if cred.scheme == AuthScheme::Ntlm => {
            // First leg: bare "NTLM" → Type 1. Second leg: "NTLM <type2>" → Type 3.
            match challenge.split_whitespace().nth(1) {
                Some(type2) => {
                    let nonce: [u8; 8] = rand::random();
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64 / 100 + 116_444_736_000_000_000)
                        .unwrap_or(0);
                    let (domain, user) = match cred.username.split_once('\\') {
                        Some((d, u)) => (d.to_string(), u.to_string()),
                        None => (String::new(), cred.username.clone()),
                    };
                    crate::ntlm::type3(type2, &user, &cred.password, &domain, nonce, ts)
                        .map(|t3| format!("NTLM {t3}"))
                }
                None => Some(format!("NTLM {}", crate::ntlm::type1())),
            }
        }
        "negotiate" if cred.scheme == AuthScheme::Negotiate => {
            Some(format!("Negotiate {}", "<spnego-step-1>"))
        }
        _ => None,
    }
}

pub fn basic(user: &str, pass: &str) -> String {
    let token = general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    format!("Basic {token}")
}

fn digest(challenge: &str, cred: &AuthCredential, method: &str, uri: &str) -> Option<String> {
    let realm = extract(challenge, "realm")?;
    let nonce = extract(challenge, "nonce")?;
    let qop = extract(challenge, "qop");
    let algorithm = extract(challenge, "algorithm").unwrap_or_else(|| "MD5".to_string());
    let opaque = extract(challenge, "opaque");
    if algorithm != "MD5" {
        // SHA-256 etc. would require swapping the hasher — left for a follow-up.
        return None;
    }
    let ha1 = md5_hex(&format!("{}:{}:{}", cred.username, realm, cred.password));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    let nc = "00000001";
    let cnonce: String = (0..16)
        .map(|_| {
            let b: u8 = rand::thread_rng().gen_range(0..16);
            format!("{b:x}")
        })
        .collect();
    let response = match qop.as_deref() {
        Some("auth") | Some("auth-int") => md5_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")),
        _ => md5_hex(&format!("{ha1}:{nonce}:{ha2}")),
    };

    let mut header = format!(
        "Digest username=\"{u}\", realm=\"{r}\", nonce=\"{n}\", uri=\"{uri}\", response=\"{response}\"",
        u = cred.username,
        r = realm,
        n = nonce,
    );
    if let Some(q) = qop {
        header.push_str(&format!(", qop={q}, nc={nc}, cnonce=\"{cnonce}\""));
    }
    if let Some(o) = opaque {
        header.push_str(&format!(", opaque=\"{o}\""));
    }
    if algorithm != "MD5" {
        header.push_str(&format!(", algorithm={algorithm}"));
    }
    Some(header)
}

fn extract(haystack: &str, key: &str) -> Option<String> {
    let rx = Regex::new(&format!(r#"(?i)\b{key}\s*=\s*(?:"([^"]*)"|([^,\s]+))"#)).ok()?;
    let cap = rx.captures(haystack)?;
    Some(
        cap.get(1)
            .or_else(|| cap.get(2))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default(),
    )
}

fn md5_hex(s: &str) -> String {
    let digest = Md5::digest(s.as_bytes());
    hex::encode(digest)
}
