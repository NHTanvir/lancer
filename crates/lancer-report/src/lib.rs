//! Report generation. Implemented formats:
//!
//! - HTML (interactive single-file)
//! - JSON
//! - Markdown
//! - SARIF 2.1.0 (for CI integrations)
//! - XML (Burp-compatible-ish)
//!
//! All formats take a slice of `Issue` (from `lancer_storage`) plus a
//! `ReportMeta` (title, project name, generated_at).

pub mod exporters;
pub mod pdf;
pub mod templates;
pub mod tera_tpl;

pub use pdf::render_pdf;
pub use tera_tpl::{render as render_tera, DEFAULT_TEMPLATE as DEFAULT_TERA_TEMPLATE};

use chrono::{DateTime, Utc};
use lancer_storage::issues::{Confidence, Issue, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMeta {
    pub project_name: String,
    pub title: String,
    pub generated_at: DateTime<Utc>,
    pub tester: Option<String>,
    pub executive_summary: Option<String>,
}

impl ReportMeta {
    pub fn new(project: impl Into<String>) -> Self {
        Self {
            project_name: project.into(),
            title: "Lancer security assessment".to_string(),
            generated_at: Utc::now(),
            tester: None,
            executive_summary: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReportFilter {
    pub min_severity: Option<Severity>,
    pub min_confidence: Option<Confidence>,
    pub include_fp: bool,
    pub host_filter: Option<String>,
}

impl ReportFilter {
    pub fn keep(&self, issue: &Issue) -> bool {
        if !self.include_fp && issue.false_positive {
            return false;
        }
        if let Some(s) = self.min_severity {
            if severity_rank(issue.severity) < severity_rank(s) {
                return false;
            }
        }
        if let Some(c) = self.min_confidence {
            if confidence_rank(issue.confidence) < confidence_rank(c) {
                return false;
            }
        }
        if let Some(h) = &self.host_filter {
            if !issue.host.contains(h) {
                return false;
            }
        }
        true
    }
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn confidence_rank(c: Confidence) -> u8 {
    match c {
        Confidence::Tentative => 0,
        Confidence::Firm => 1,
        Confidence::Certain => 2,
    }
}

pub fn render_json(meta: &ReportMeta, issues: &[Issue], filter: &ReportFilter) -> String {
    let kept: Vec<&Issue> = issues.iter().filter(|i| filter.keep(i)).collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "meta": meta,
        "summary": severity_counts(&kept),
        "issues": kept,
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

pub fn render_markdown(meta: &ReportMeta, issues: &[Issue], filter: &ReportFilter) -> String {
    use std::fmt::Write as _;
    let kept: Vec<&Issue> = issues.iter().filter(|i| filter.keep(i)).collect();
    let mut s = String::new();
    let _ = writeln!(s, "# {}", meta.title);
    let _ = writeln!(s, "\n_Project: {}_  ", meta.project_name);
    let _ = writeln!(
        s,
        "_Generated: {}_\n",
        meta.generated_at.format("%Y-%m-%d %H:%M UTC")
    );
    if let Some(es) = &meta.executive_summary {
        let _ = writeln!(s, "## Executive summary\n\n{es}\n");
    }
    let counts = severity_counts(&kept);
    let _ = writeln!(s, "## Summary\n");
    for (k, v) in &counts {
        let _ = writeln!(s, "- {k}: {v}");
    }
    let _ = writeln!(s, "\n## Findings\n");
    for i in kept {
        let _ = writeln!(
            s,
            "### [{}/{}] {}\n",
            i.severity.as_str(),
            i.confidence.as_str(),
            i.name
        );
        let _ = writeln!(s, "**URL:** `{}`  \n", i.url);
        let _ = writeln!(s, "{}\n", i.description);
        if let Some(r) = &i.remediation {
            let _ = writeln!(s, "**Remediation:** {r}\n");
        }
    }
    s
}

pub fn render_html(meta: &ReportMeta, issues: &[Issue], filter: &ReportFilter) -> String {
    let kept: Vec<&Issue> = issues.iter().filter(|i| filter.keep(i)).collect();
    let counts = severity_counts(&kept);
    let mut s = String::new();
    s.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><title>");
    s.push_str(&html_escape(&meta.title));
    s.push_str("</title><style>");
    s.push_str(EMBEDDED_CSS);
    s.push_str("</style></head><body>\n<header><h1>");
    s.push_str(&html_escape(&meta.title));
    s.push_str("</h1><p class=\"meta\">Project: ");
    s.push_str(&html_escape(&meta.project_name));
    s.push_str(" · Generated ");
    s.push_str(&meta.generated_at.format("%Y-%m-%d %H:%M UTC").to_string());
    s.push_str("</p></header>\n");
    if let Some(es) = &meta.executive_summary {
        s.push_str("<section><h2>Executive summary</h2><p>");
        s.push_str(&html_escape(es));
        s.push_str("</p></section>\n");
    }
    s.push_str("<section><h2>Summary</h2><table class=\"summary\"><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>");
    for (k, v) in &counts {
        s.push_str(&format!(
            "<tr><td class=\"sev sev-{k}\">{k}</td><td>{v}</td></tr>"
        ));
    }
    s.push_str("</tbody></table></section>\n");

    s.push_str("<section><h2>Findings</h2>\n");
    for i in kept {
        s.push_str(&format!(
            "<article class=\"finding sev-{sev}\"><h3>{name}</h3><dl><dt>Severity</dt><dd class=\"sev sev-{sev}\">{sev}</dd><dt>Confidence</dt><dd>{conf}</dd><dt>Host</dt><dd><code>{host}</code></dd><dt>URL</dt><dd><code>{url}</code></dd></dl><p>{desc}</p>",
            sev = i.severity.as_str(),
            conf = i.confidence.as_str(),
            name = html_escape(&i.name),
            host = html_escape(&i.host),
            url = html_escape(&i.url),
            desc = html_escape(&i.description),
        ));
        if let Some(r) = &i.remediation {
            s.push_str(&format!(
                "<details><summary>Remediation</summary><p>{}</p></details>",
                html_escape(r)
            ));
        }
        s.push_str("</article>\n");
    }
    s.push_str("</section>\n</body></html>\n");
    s
}

pub fn render_xml(meta: &ReportMeta, issues: &[Issue], filter: &ReportFilter) -> String {
    use std::fmt::Write as _;
    let kept: Vec<&Issue> = issues.iter().filter(|i| filter.keep(i)).collect();
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<lancer-report>\n");
    let _ = writeln!(out, "  <title>{}</title>", xml_escape(&meta.title));
    let _ = writeln!(out, "  <project>{}</project>", xml_escape(&meta.project_name));
    let _ = writeln!(
        out,
        "  <generatedAt>{}</generatedAt>",
        meta.generated_at.to_rfc3339()
    );
    out.push_str("  <issues>\n");
    for i in kept {
        let _ = writeln!(
            out,
            "    <issue><name>{name}</name><severity>{sev}</severity><confidence>{conf}</confidence><host>{host}</host><url>{url}</url><description>{desc}</description><remediation>{rem}</remediation></issue>",
            name = xml_escape(&i.name),
            sev = i.severity.as_str(),
            conf = i.confidence.as_str(),
            host = xml_escape(&i.host),
            url = xml_escape(&i.url),
            desc = xml_escape(&i.description),
            rem = xml_escape(i.remediation.as_deref().unwrap_or("")),
        );
    }
    out.push_str("  </issues>\n</lancer-report>\n");
    out
}

pub fn render_sarif(meta: &ReportMeta, issues: &[Issue], filter: &ReportFilter) -> String {
    let kept: Vec<&Issue> = issues.iter().filter(|i| filter.keep(i)).collect();
    let rules: std::collections::BTreeMap<String, &Issue> = kept
        .iter()
        .filter_map(|i| i.check_id.as_ref().map(|id| (id.clone(), *i)))
        .collect();
    let sarif = serde_json::json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Lancer",
                    "informationUri": "https://github.com/lancer-sec/lancer",
                    "rules": rules.iter().map(|(id, i)| serde_json::json!({
                        "id": id,
                        "shortDescription": { "text": i.name },
                        "fullDescription": { "text": i.description },
                    })).collect::<Vec<_>>(),
                }
            },
            "results": kept.iter().map(|i| serde_json::json!({
                "ruleId": i.check_id.clone().unwrap_or_else(|| "lancer.misc".into()),
                "level": match i.severity {
                    Severity::Info => "note",
                    Severity::Low => "note",
                    Severity::Medium => "warning",
                    Severity::High | Severity::Critical => "error",
                },
                "message": { "text": i.description },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": i.url }
                    }
                }]
            })).collect::<Vec<_>>(),
            "invocations": [{
                "executionSuccessful": true,
                "endTimeUtc": meta.generated_at.to_rfc3339(),
            }],
        }]
    });
    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

fn severity_counts(issues: &[&Issue]) -> Vec<(&'static str, usize)> {
    let mut counts: std::collections::BTreeMap<u8, usize> = Default::default();
    for i in issues {
        *counts.entry(severity_rank(i.severity)).or_insert(0) += 1;
    }
    let names = ["info", "low", "medium", "high", "critical"];
    (0..5u8)
        .map(|r| (names[r as usize], counts.get(&r).copied().unwrap_or(0)))
        .collect()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn xml_escape(s: &str) -> String {
    html_escape(s)
}

const EMBEDDED_CSS: &str = r#"
* { box-sizing: border-box; }
body { font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 1100px; margin: 2rem auto; color: #222; padding: 0 1rem; }
header h1 { margin: 0; font-size: 1.6rem; }
.meta { color: #666; }
table.summary { border-collapse: collapse; }
table.summary th, table.summary td { padding: 4px 12px; border-bottom: 1px solid #eee; text-align: left; }
.sev { font-weight: 600; text-transform: capitalize; padding: 2px 8px; border-radius: 4px; display: inline-block; }
.sev-info { background: #e7ecf3; color: #364a63; }
.sev-low { background: #fff4d6; color: #6a5300; }
.sev-medium { background: #fde2c8; color: #6f3600; }
.sev-high { background: #fcd0d0; color: #6a1212; }
.sev-critical { background: #2d1010; color: #fff; }
.finding { border: 1px solid #eee; border-left: 4px solid #999; padding: 12px 16px; margin: 14px 0; border-radius: 6px; }
.finding.sev-high, .finding.sev-critical { border-left-color: #cc1f1f; }
.finding.sev-medium { border-left-color: #d97000; }
.finding.sev-low { border-left-color: #a37a00; }
.finding h3 { margin-top: 0; }
dl { display: grid; grid-template-columns: 110px 1fr; gap: 4px 12px; margin: 0 0 8px; }
dt { color: #666; }
dd { margin: 0; }
code { background: #f6f7f9; padding: 1px 6px; border-radius: 3px; }
"#;
