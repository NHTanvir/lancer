//! Scanner-issues store (used by Phase 4).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        // Case-insensitive: the GUI uses the serialized (capitalized) form
        // "Info"/"Low"/"Medium"/"High"/"Critical", so a lowercase-only match
        // silently dropped every user-set severity back to the Info default.
        Some(match s.to_ascii_lowercase().as_str() {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    Tentative,
    Firm,
    Certain,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Tentative => "tentative",
            Confidence::Firm => "firm",
            Confidence::Certain => "certain",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        // Case-insensitive — see Severity::parse. The GUI sends "Tentative"/
        // "Firm"/"Certain", which a lowercase-only match would reject.
        Some(match s.to_ascii_lowercase().as_str() {
            "tentative" => Confidence::Tentative,
            "firm" => Confidence::Firm,
            "certain" => Confidence::Certain,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub id: Uuid,
    pub found_at: DateTime<Utc>,
    pub host: String,
    pub url: String,
    pub name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub description: String,
    pub remediation: Option<String>,
    pub history_id: Option<Uuid>,
    pub check_id: Option<String>,
    pub false_positive: bool,
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub evidence_request: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub evidence_response: Option<Vec<u8>>,
}

impl Issue {
    pub fn new(
        host: impl Into<String>,
        url: impl Into<String>,
        name: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            found_at: Utc::now(),
            host: host.into(),
            url: url.into(),
            name: name.into(),
            severity,
            confidence,
            description: description.into(),
            remediation: None,
            history_id: None,
            check_id: None,
            false_positive: false,
            notes: None,
            evidence_request: None,
            evidence_response: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IssueStore {
    pool: SqlitePool,
}

impl IssueStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, issue: &Issue) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO issues(id, found_at, host, url, name, severity, confidence,
                description, remediation, evidence_request, evidence_response,
                history_id, check_id, false_positive, notes)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(issue.id.to_string())
        .bind(issue.found_at)
        .bind(&issue.host)
        .bind(&issue.url)
        .bind(&issue.name)
        .bind(issue.severity.as_str())
        .bind(issue.confidence.as_str())
        .bind(&issue.description)
        .bind(&issue.remediation)
        .bind(&issue.evidence_request)
        .bind(&issue.evidence_response)
        .bind(issue.history_id.map(|x| x.to_string()))
        .bind(&issue.check_id)
        .bind(issue.false_positive as i64)
        .bind(&issue.notes)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list(&self) -> anyhow::Result<Vec<Issue>> {
        let rows = sqlx::query("SELECT * FROM issues ORDER BY found_at DESC")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let id_str: String = r.try_get("id")?;
            let history_id_str: Option<String> = r.try_get("history_id")?;
            let severity_str: String = r.try_get("severity")?;
            let confidence_str: String = r.try_get("confidence")?;
            out.push(Issue {
                id: Uuid::parse_str(&id_str)?,
                found_at: r.try_get("found_at")?,
                host: r.try_get("host")?,
                url: r.try_get("url")?,
                name: r.try_get("name")?,
                severity: Severity::parse(&severity_str).unwrap_or(Severity::Info),
                confidence: Confidence::parse(&confidence_str).unwrap_or(Confidence::Tentative),
                description: r.try_get("description")?,
                remediation: r.try_get("remediation")?,
                history_id: history_id_str
                    .as_deref()
                    .and_then(|s| Uuid::parse_str(s).ok()),
                check_id: r.try_get("check_id")?,
                false_positive: r.try_get::<i64, _>("false_positive")? != 0,
                notes: r.try_get("notes")?,
                evidence_request: r.try_get("evidence_request").ok(),
                evidence_response: r.try_get("evidence_response").ok(),
            });
        }
        Ok(out)
    }

    pub async fn mark_false_positive(&self, id: Uuid, fp: bool) -> anyhow::Result<()> {
        sqlx::query("UPDATE issues SET false_positive = ? WHERE id = ?")
            .bind(fp as i64)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Manual analyst override of severity and/or confidence on an issue.
    pub async fn update_severity_confidence(
        &self,
        id: Uuid,
        severity: Option<Severity>,
        confidence: Option<Confidence>,
    ) -> anyhow::Result<()> {
        if let Some(s) = severity {
            sqlx::query("UPDATE issues SET severity = ? WHERE id = ?")
                .bind(s.as_str())
                .bind(id.to_string())
                .execute(&self.pool)
                .await?;
        }
        if let Some(c) = confidence {
            sqlx::query("UPDATE issues SET confidence = ? WHERE id = ?")
                .bind(c.as_str())
                .bind(id.to_string())
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }
}
