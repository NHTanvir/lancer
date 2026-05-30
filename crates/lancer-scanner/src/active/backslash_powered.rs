//! §46 Unknown-Injection Scanner — backslash-powered-scanner equivalent.
//!
//! Send probe payloads designed to break parsers in distinctive ways, then
//! diff each response against a baseline (status, length, body word
//! frequency, error-message presence). An injection point is anomalous if the
//! response signature for `\` differs from baseline AND from `\\` (so we can
//! rule out simple escaping).

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

pub struct BackslashPoweredCheck;

/// Diagnostic payloads — break parsers in distinctive ways.
const PROBES: &[(&str, &str)] = &[
    ("\\",        "single backslash"),
    ("\\\\",      "escaped backslash"),
    ("\\0",       "null escape"),
    ("'",         "single quote"),
    ("\"",        "double quote"),
    ("${1}",      "shell/template expansion"),
    ("{{1}}",     "Jinja-style"),
    ("<%=1%>",    "ERB/JSP"),
    ("(){}",      "balanced parens"),
    ("[1]",       "array literal"),
    ("&apos;",    "HTML entity"),
    ("\u{00FF}",  "high byte"),
    ("\n",        "newline"),
    ("\r\n",      "CRLF"),
];

/// Lightweight response signature for diffing.
#[derive(Debug, Clone, Default)]
struct Sig {
    status: u16,
    length: usize,
    word_count: usize,
    has_error: bool,
}

fn classify(resp: &lancer_core::HttpResponse) -> Sig {
    let body = resp.body_text().unwrap_or("");
    let word_count = body.split_whitespace().count();
    let lower = body.to_ascii_lowercase();
    let has_error = lower.contains("error")
        || lower.contains("exception")
        || lower.contains("stack")
        || lower.contains("traceback")
        || lower.contains("warning")
        || lower.contains("syntax");
    Sig {
        status: resp.status,
        length: resp.body.len(),
        word_count,
        has_error,
    }
}

/// Quantify how different two signatures are. Returns 0.0–1.0.
fn divergence(a: &Sig, b: &Sig) -> f64 {
    let mut score = 0.0;
    if a.status != b.status { score += 0.4; }
    let len_delta = (a.length as i64 - b.length as i64).abs() as f64;
    let len_score = (len_delta / (a.length.max(b.length).max(1)) as f64).min(0.3);
    score += len_score;
    let word_delta = (a.word_count as i64 - b.word_count as i64).abs() as f64;
    score += (word_delta / 100.0).min(0.2);
    if a.has_error != b.has_error { score += 0.2; }
    score.min(1.0)
}

/// Inject `payload` into the URL query as a value (lightweight insertion).
fn build_probe(base: &HttpRequest, payload: &str) -> HttpRequest {
    let mut req = base.clone();
    let path = &req.path;
    let sep = if path.contains('?') { '&' } else { '?' };
    let qenc = urlencode(payload);
    req.path = format!("{path}{sep}lancer_probe={qenc}");
    req
}

fn urlencode(s: &str) -> String {
    s.chars().map(|c| match c {
        '0'..='9' | 'a'..='z' | 'A'..='Z' | '-' | '.' | '_' | '~' => c.to_string(),
        _ => {
            let mut buf = [0u8; 4];
            let bytes = c.encode_utf8(&mut buf).as_bytes().to_vec();
            bytes.iter().map(|b| format!("%{b:02X}")).collect::<Vec<_>>().join("")
        }
    }).collect()
}

#[async_trait]
impl ActiveCheck for BackslashPoweredCheck {
    fn id(&self) -> &'static str { "active.backslash_powered" }
    fn name(&self) -> &'static str { "Unknown-injection (response-diff anomaly)" }

    async fn run(&self, client: &HttpClient, base: &HttpRequest, _point: &InsertionPoint) -> Vec<Issue> {
        let Ok(baseline_resp) = client.send(base).await else { return Vec::new() };
        let baseline = classify(&baseline_resp);

        let mut results: Vec<(String, String, Sig)> = Vec::new();
        for (payload, label) in PROBES {
            let probe = build_probe(base, payload);
            let Ok(resp) = client.send(&probe).await else { continue };
            results.push((payload.to_string(), label.to_string(), classify(&resp)));
        }

        // Find the maximum-divergence probe vs baseline.
        let mut max: Option<(String, String, Sig, f64)> = None;
        for (payload, label, sig) in &results {
            let d = divergence(sig, &baseline);
            if max.as_ref().map_or(true, |(_, _, _, md)| d > *md) {
                max = Some((payload.clone(), label.clone(), sig.clone(), d));
            }
        }

        let Some((payload, label, sig, div)) = max else { return Vec::new() };
        if div < 0.35 { return Vec::new(); }

        // Rule out trivial escaping: divergence of `\\` should be smaller than `\` if it's truly an unknown injection.
        let single_div = results.iter()
            .find(|(p, _, _)| p == "\\")
            .map(|(_, _, s)| divergence(s, &baseline))
            .unwrap_or(0.0);
        let double_div = results.iter()
            .find(|(p, _, _)| p == "\\\\")
            .map(|(_, _, s)| divergence(s, &baseline))
            .unwrap_or(0.0);

        let confidence = if single_div > double_div + 0.1 {
            Confidence::Firm
        } else {
            Confidence::Tentative
        };

        let mut i = Issue::new(
            base.meta.host.clone(),
            base.url(),
            "Unknown injection class — manual investigation",
            if div > 0.7 { Severity::High } else { Severity::Medium },
            confidence,
            format!(
                "Probe `{label}` ({payload:?}) produced response signature divergence {div:.2} vs baseline (status {} → {}, len {} → {}). Investigate manually.",
                baseline.status, sig.status, baseline.length, sig.length
            ),
        );
        i.remediation = Some(
            "Investigate the parser handling this parameter; an anomalous response to a non-standard escape often indicates an injection vector.".into(),
        );
        i.check_id = Some(self.id().into());
        vec![i]
    }
}
