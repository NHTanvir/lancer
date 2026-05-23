//! Per-stakeholder report templates.

use lancer_storage::issues::{Issue, Severity};

use crate::ReportMeta;

/// One-page executive summary: counts + top three findings, plain English.
pub fn executive_summary(meta: &ReportMeta, issues: &[Issue]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "# {} — executive summary\n", meta.title);
    let _ = writeln!(s, "_{}, generated {}_\n", meta.project_name, meta.generated_at.format("%Y-%m-%d"));
    let crit = count(issues, Severity::Critical);
    let high = count(issues, Severity::High);
    let med = count(issues, Severity::Medium);
    let low = count(issues, Severity::Low);
    let _ = writeln!(s, "**Posture overview:** {crit} critical · {high} high · {med} medium · {low} low.\n");
    if let Some(es) = &meta.executive_summary {
        let _ = writeln!(s, "{es}\n");
    }
    let mut top: Vec<&Issue> = issues
        .iter()
        .filter(|i| matches!(i.severity, Severity::Critical | Severity::High))
        .collect();
    top.sort_by_key(|i| match i.severity {
        Severity::Critical => 0,
        Severity::High => 1,
        _ => 2,
    });
    let _ = writeln!(s, "## Top findings\n");
    for i in top.iter().take(3) {
        let _ = writeln!(s, "- **{}** — {}", i.name, i.description);
    }
    s
}

/// Developer-detail flavour: full per-issue blocks with technical
/// reproduction, in Markdown.
pub fn developer_detail(meta: &ReportMeta, issues: &[Issue]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "# {} — developer detail\n", meta.title);
    for i in issues {
        let _ = writeln!(
            s,
            "## [{}/{}] {}\n",
            i.severity.as_str(),
            i.confidence.as_str(),
            i.name
        );
        let _ = writeln!(s, "- Host: `{}`", i.host);
        let _ = writeln!(s, "- URL: `{}`", i.url);
        if let Some(check) = &i.check_id {
            let _ = writeln!(s, "- Check: `{check}`");
        }
        let _ = writeln!(s, "\n{}\n", i.description);
        if let Some(r) = &i.remediation {
            let _ = writeln!(s, "**Remediation:** {r}\n");
        }
        if let Some(n) = &i.notes {
            let _ = writeln!(s, "**Notes:** {n}\n");
        }
    }
    s
}

fn count(issues: &[Issue], s: Severity) -> usize {
    issues.iter().filter(|i| i.severity == s).count()
}
