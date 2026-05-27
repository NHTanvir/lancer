//! AI-powered findings triage.
//!
//! Provides CVSS 3.1 scoring suggestions, duplicate detection,
//! and AI-drafted vulnerability reports via lancer-ai.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Data types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub title: String,
    pub severity: String,
    pub cvss: Option<String>,
    pub program: Option<String>,
    pub endpoint: Option<String>,
    pub impact: Option<String>,
    pub repro: Option<String>,
    pub tags: Option<String>,
    pub status: FindingStatus,
    pub raw_request: Option<String>,
    pub raw_response: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FindingStatus {
    Draft,
    Ready,
    Submitted,
    Triaged,
    Resolved,
    Paid,
    Duplicate,
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Draft     => "draft",
            Self::Ready     => "ready",
            Self::Submitted => "submitted",
            Self::Triaged   => "triaged",
            Self::Resolved  => "resolved",
            Self::Paid      => "paid",
            Self::Duplicate => "duplicate",
        };
        write!(f, "{s}")
    }
}

/// Result of AI triage on a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    pub finding_id: Uuid,
    pub cvss_vector: String,
    pub base_score: f32,
    pub reasoning: String,
    pub suggested_severity: String,
}

/// Result of duplicate detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateMatch {
    pub finding_id: Uuid,
    pub duplicate_of: Uuid,
    pub similarity: f32,
    pub reason: String,
}

// ── CVSS 3.1 heuristic scorer ─────────────────────────────────────────────────

/// Derive a rough CVSS 3.1 vector from a finding's title and tags.
/// A real implementation would call lancer-ai for precise scoring.
pub fn heuristic_cvss(finding: &Finding) -> TriageResult {
    let title_lower = finding.title.to_lowercase();
    let tags = finding.tags.as_deref().unwrap_or("").to_lowercase();

    let (vector, score, severity, reasoning) = if title_lower.contains("rce")
        || title_lower.contains("remote code")
        || title_lower.contains("command injection")
    {
        (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            10.0f32,
            "Critical",
            "Remote code execution with network access vector, no authentication required, scope change, full C/I/A impact.",
        )
    } else if title_lower.contains("sqli") || title_lower.contains("sql injection") {
        (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
            9.4,
            "Critical",
            "SQL injection typically allows full database access. High confidentiality and integrity impact.",
        )
    } else if title_lower.contains("xss") || tags.contains("xss") {
        (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            6.1,
            "Medium",
            "Reflected/stored XSS requires user interaction, scope change. Low C/I impact per session.",
        )
    } else if title_lower.contains("ssrf") {
        (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            7.5,
            "High",
            "SSRF can expose internal services and metadata. High confidentiality impact.",
        )
    } else if title_lower.contains("idor") || title_lower.contains("broken access") {
        (
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            8.1,
            "High",
            "IDOR allows access to other users' data. High C/I impact with low-privilege authentication.",
        )
    } else if title_lower.contains("redirect") {
        (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            4.3,
            "Medium",
            "Open redirect enables phishing attacks. Low integrity impact requiring user interaction.",
        )
    } else {
        (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            5.3,
            "Medium",
            "Generic information disclosure or low-impact finding. Manual review recommended for precise scoring.",
        )
    };

    TriageResult {
        finding_id: finding.id,
        cvss_vector: vector.to_string(),
        base_score: score,
        reasoning: reasoning.to_string(),
        suggested_severity: severity.to_string(),
    }
}

// ── Duplicate detection ───────────────────────────────────────────────────────

/// Compute a simple similarity score between two findings (0.0–1.0).
fn endpoint_similarity(a: &Finding, b: &Finding) -> f32 {
    let ep_a = a.endpoint.as_deref().unwrap_or("").to_lowercase();
    let ep_b = b.endpoint.as_deref().unwrap_or("").to_lowercase();
    if ep_a.is_empty() || ep_b.is_empty() { return 0.0; }
    if ep_a == ep_b { return 1.0; }
    // Jaccard on path segments
    let segs_a: std::collections::HashSet<&str> = ep_a.split('/').filter(|s| !s.is_empty()).collect();
    let segs_b: std::collections::HashSet<&str> = ep_b.split('/').filter(|s| !s.is_empty()).collect();
    if segs_a.is_empty() && segs_b.is_empty() { return 0.0; }
    let inter = segs_a.intersection(&segs_b).count() as f32;
    let union = segs_a.union(&segs_b).count() as f32;
    inter / union
}

fn title_similarity(a: &Finding, b: &Finding) -> f32 {
    let ta = a.title.to_lowercase();
    let tb = b.title.to_lowercase();
    let words_a: std::collections::HashSet<&str> = ta.split_whitespace().collect();
    let words_b: std::collections::HashSet<&str> = tb.split_whitespace().collect();
    if words_a.is_empty() && words_b.is_empty() { return 1.0; }
    let inter = words_a.intersection(&words_b).count() as f32;
    let union = words_a.union(&words_b).count() as f32;
    inter / union
}

/// Find potential duplicates in a list of findings.
pub fn find_duplicates(findings: &[Finding]) -> Vec<DuplicateMatch> {
    let mut matches = Vec::new();
    for i in 0..findings.len() {
        for j in (i + 1)..findings.len() {
            let a = &findings[i];
            let b = &findings[j];
            if a.severity != b.severity { continue; }
            let ep_sim = endpoint_similarity(a, b);
            let title_sim = title_similarity(a, b);
            let combined = ep_sim * 0.6 + title_sim * 0.4;
            if combined >= 0.75 {
                matches.push(DuplicateMatch {
                    finding_id: b.id,
                    duplicate_of: a.id,
                    similarity: combined,
                    reason: format!(
                        "Endpoint similarity {:.0}%, title similarity {:.0}%",
                        ep_sim * 100.0, title_sim * 100.0
                    ),
                });
            }
        }
    }
    matches
}

// ── Report draft ──────────────────────────────────────────────────────────────

/// Generate a markdown report draft from a finding.
pub fn draft_report(finding: &Finding) -> String {
    let severity = &finding.severity;
    let title = &finding.title;
    let endpoint = finding.endpoint.as_deref().unwrap_or("(not specified)");
    let impact = finding.impact.as_deref().unwrap_or("(not specified)");
    let repro = finding.repro.as_deref().unwrap_or("(not specified)");
    let cvss = finding.cvss.as_deref().unwrap_or("(not scored)");
    let program = finding.program.as_deref().unwrap_or("(not specified)");

    format!(
        "# {title}\n\n\
        **Severity:** {severity}  \n\
        **CVSS:** {cvss}  \n\
        **Program:** {program}  \n\
        **Endpoint:** `{endpoint}`\n\n\
        ## Summary\n\n\
        {title} was identified on `{endpoint}`.\n\n\
        ## Impact\n\n\
        {impact}\n\n\
        ## Reproduction Steps\n\n\
        {repro}\n\n\
        ## Evidence\n\n\
        ```http\n{req}\n```\n\n\
        ## Remediation\n\n\
        {remediation}\n",
        req = finding.raw_request.as_deref().unwrap_or("(attach request/response)"),
        remediation = generic_remediation(title),
    )
}

fn generic_remediation(title: &str) -> &'static str {
    let t = title.to_lowercase();
    if t.contains("xss") {
        "Encode all user-supplied data before rendering in HTML context. Implement a strict Content Security Policy (CSP)."
    } else if t.contains("sql") {
        "Use parameterised queries or prepared statements. Never concatenate user input into SQL strings."
    } else if t.contains("ssrf") {
        "Whitelist allowed internal hosts. Block requests to metadata services (169.254.169.254). Validate and sanitise all URLs supplied by users."
    } else if t.contains("idor") || t.contains("access") {
        "Implement server-side authorisation checks on every resource access. Never rely solely on client-supplied identifiers."
    } else if t.contains("redirect") {
        "Validate redirect destinations against a strict allowlist. Avoid passing full URLs as parameters; use opaque tokens instead."
    } else {
        "Apply input validation, output encoding, and the principle of least privilege. Conduct a full security review of the affected functionality."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(title: &str, endpoint: &str) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            title: title.into(),
            severity: "High".into(),
            cvss: None,
            program: None,
            endpoint: Some(endpoint.into()),
            impact: None,
            repro: None,
            tags: None,
            status: FindingStatus::Draft,
            raw_request: None,
            raw_response: None,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn heuristic_cvss_xss() {
        let f = make_finding("Reflected XSS in search", "/search");
        let t = heuristic_cvss(&f);
        assert!(t.base_score > 0.0 && t.base_score < 10.0);
        assert_eq!(t.suggested_severity, "Medium");
    }

    #[test]
    fn duplicate_detection_same_endpoint() {
        let a = make_finding("XSS in bio", "/api/profile");
        let b = make_finding("XSS stored in profile", "/api/profile");
        let dups = find_duplicates(&[a, b]);
        assert!(!dups.is_empty());
        assert!(dups[0].similarity >= 0.75);
    }

    #[test]
    fn draft_report_contains_title() {
        let f = make_finding("Reflected XSS", "/search");
        let report = draft_report(&f);
        assert!(report.contains("Reflected XSS"));
    }
}
