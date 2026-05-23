//! Issue-tracker / vuln-management exporters.
//!
//! Each function takes a slice of issues and returns a JSON payload (or list
//! of payloads) that can be POSTed to the corresponding API. We don't make
//! HTTP calls here — callers handle authentication / rate-limits / retries.

use lancer_storage::issues::{Confidence, Issue, Severity};
use serde::Serialize;

/// Jira "create issue" payload (v3 REST API).
#[derive(Debug, Serialize)]
pub struct JiraIssue {
    pub fields: JiraFields,
}

#[derive(Debug, Serialize)]
pub struct JiraFields {
    pub project: JiraKey,
    pub summary: String,
    pub description: String,
    pub issuetype: JiraKey,
    pub labels: Vec<String>,
    pub priority: JiraKey,
}

#[derive(Debug, Serialize)]
pub struct JiraKey {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

pub fn jira(project_key: &str, issues: &[Issue]) -> Vec<JiraIssue> {
    issues
        .iter()
        .map(|i| JiraIssue {
            fields: JiraFields {
                project: JiraKey { key: Some(project_key.to_string()), name: None },
                summary: format!("[{}] {}", i.severity.as_str(), i.name),
                description: build_description(i),
                issuetype: JiraKey { key: None, name: Some("Bug".into()) },
                labels: vec![
                    format!("severity:{}", i.severity.as_str()),
                    format!("confidence:{}", i.confidence.as_str()),
                    "lancer".into(),
                ],
                priority: JiraKey { key: None, name: Some(jira_priority(i.severity).into()) },
            },
        })
        .collect()
}

fn jira_priority(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Highest",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Lowest",
    }
}

#[derive(Debug, Serialize)]
pub struct LinearIssueCreate {
    pub title: String,
    pub description: String,
    pub labels: Vec<String>,
    pub priority: u8,
}

pub fn linear(issues: &[Issue]) -> Vec<LinearIssueCreate> {
    issues
        .iter()
        .map(|i| LinearIssueCreate {
            title: format!("[{}] {}", i.severity.as_str(), i.name),
            description: build_description(i),
            labels: vec![
                "lancer".into(),
                format!("severity:{}", i.severity.as_str()),
            ],
            priority: linear_priority(i.severity),
        })
        .collect()
}

fn linear_priority(s: Severity) -> u8 {
    match s {
        Severity::Critical => 1,
        Severity::High => 2,
        Severity::Medium => 3,
        Severity::Low => 4,
        Severity::Info => 0,
    }
}

#[derive(Debug, Serialize)]
pub struct GithubIssue {
    pub title: String,
    pub body: String,
    pub labels: Vec<String>,
}

pub fn github(issues: &[Issue]) -> Vec<GithubIssue> {
    issues
        .iter()
        .map(|i| GithubIssue {
            title: format!("[{}] {}", i.severity.as_str(), i.name),
            body: build_description(i),
            labels: vec![
                "security".into(),
                format!("severity:{}", i.severity.as_str()),
                format!("confidence:{}", i.confidence.as_str()),
            ],
        })
        .collect()
}

#[derive(Debug, Serialize)]
pub struct DefectDojoFinding {
    pub title: String,
    pub date: String,
    pub severity: String,
    pub description: String,
    pub mitigation: String,
    pub impact: String,
    pub url: String,
    pub active: bool,
    pub verified: bool,
}

pub fn defectdojo(issues: &[Issue]) -> Vec<DefectDojoFinding> {
    issues
        .iter()
        .map(|i| DefectDojoFinding {
            title: i.name.clone(),
            date: i.found_at.format("%Y-%m-%d").to_string(),
            severity: defectdojo_severity(i.severity).into(),
            description: i.description.clone(),
            mitigation: i.remediation.clone().unwrap_or_default(),
            impact: confidence_label(i.confidence).into(),
            url: i.url.clone(),
            active: !i.false_positive,
            verified: matches!(i.confidence, Confidence::Firm | Confidence::Certain),
        })
        .collect()
}

fn defectdojo_severity(s: Severity) -> &'static str {
    match s {
        Severity::Info => "Info",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

fn confidence_label(c: Confidence) -> &'static str {
    match c {
        Confidence::Tentative => "Tentative — confirm manually",
        Confidence::Firm => "Firm — high probability of true positive",
        Confidence::Certain => "Certain — exploitable",
    }
}

/// Faraday-compatible CSV export. One row per issue.
pub fn faraday_csv(issues: &[Issue]) -> String {
    let mut out = String::from("name,severity,host,target,description,resolution,external_id\n");
    for i in issues {
        out.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            csv_field(&i.name),
            i.severity.as_str(),
            csv_field(&i.host),
            csv_field(&i.url),
            csv_field(&i.description),
            csv_field(i.remediation.as_deref().unwrap_or("")),
            i.id,
        ));
    }
    out
}

fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn build_description(i: &Issue) -> String {
    let mut s = String::new();
    s.push_str(&format!("**Host:** {}\n", i.host));
    s.push_str(&format!("**URL:** {}\n\n", i.url));
    s.push_str(&format!("{}\n", i.description));
    if let Some(rem) = &i.remediation {
        s.push_str(&format!("\n**Remediation:** {rem}\n"));
    }
    if let Some(n) = &i.notes {
        s.push_str(&format!("\n**Notes:** {n}\n"));
    }
    s
}
