//! Organizer: tagged library of saved interesting requests.

use chrono::{DateTime, Utc};
use lancer_core::{HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizerEntry {
    pub id: Uuid,
    pub title: String,
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub added_at: DateTime<Utc>,
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
}

#[derive(Debug, Clone)]
pub struct OrganizerStore {
    pool: SqlitePool,
}

impl OrganizerStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, entry: &OrganizerEntry) -> anyhow::Result<()> {
        let req_blob = serde_json::to_vec(&entry.request)?;
        let resp_blob = match &entry.response {
            Some(r) => Some(serde_json::to_vec(r)?),
            None => None,
        };
        sqlx::query(
            "INSERT INTO organizer(id, title, tags, notes, request_blob, response_blob, added_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(entry.id.to_string())
        .bind(&entry.title)
        .bind(entry.tags.join(","))
        .bind(&entry.notes)
        .bind(req_blob)
        .bind(resp_blob)
        .bind(entry.added_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list(&self) -> anyhow::Result<Vec<OrganizerEntry>> {
        let rows = sqlx::query("SELECT * FROM organizer ORDER BY added_at DESC")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let id_str: String = r.try_get("id")?;
            let req_blob: Vec<u8> = r.try_get("request_blob")?;
            let resp_blob: Option<Vec<u8>> = r.try_get("response_blob")?;
            let tags_str: String = r.try_get("tags")?;
            let request: HttpRequest = serde_json::from_slice(&req_blob)?;
            let response: Option<HttpResponse> = match resp_blob {
                Some(b) if !b.is_empty() => Some(serde_json::from_slice(&b)?),
                _ => None,
            };
            out.push(OrganizerEntry {
                id: Uuid::parse_str(&id_str)?,
                title: r.try_get("title")?,
                tags: tags_str
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect(),
                notes: r.try_get("notes")?,
                added_at: r.try_get("added_at")?,
                request,
                response,
            });
        }
        Ok(out)
    }

    pub async fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM organizer WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
