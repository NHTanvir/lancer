//! HTTP history (Proxy → History tab).

use chrono::{DateTime, Utc};
use lancer_core::{HttpRequest, HttpResponse, MimeKind};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

/// One row of HTTP history (request + optional response).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRecord {
    pub id: Uuid,
    pub captured_at: DateTime<Utc>,
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub method: String,
    pub path: String,
    pub status: Option<i64>,
    pub response_length: Option<i64>,
    pub mime: Option<String>,
    pub tool_generated: bool,
    pub color: Option<String>,
    pub comment: Option<String>,
    pub in_scope: bool,
    pub elapsed_ms: Option<i64>,
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
}

#[derive(Debug, Default, Clone)]
pub struct HistoryFilter {
    pub host: Option<String>,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub mime: Option<MimeKind>,
    pub search: Option<String>,
    pub only_in_scope: bool,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct HistoryStore {
    pool: SqlitePool,
}

impl HistoryStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert a new request-only entry. Returns the row id.
    pub async fn insert_request(&self, req: &HttpRequest, in_scope: bool) -> anyhow::Result<Uuid> {
        let id = req.meta.id;
        let req_blob = serde_json::to_vec(req)?;
        sqlx::query(
            "INSERT INTO history(id, captured_at, host, port, scheme, method, path,
                status, response_length, mime, tool_generated, color, comment, in_scope,
                request_blob, response_blob, elapsed_ms)
             VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, ?, ?, ?, NULL, NULL)",
        )
        .bind(id.to_string())
        .bind(req.meta.captured_at)
        .bind(&req.meta.host)
        .bind(req.meta.port as i64)
        .bind(&req.meta.scheme)
        .bind(req.method.as_str())
        .bind(&req.path)
        .bind(req.meta.tool_generated as i64)
        .bind(&req.meta.color)
        .bind(&req.meta.comment)
        .bind(in_scope as i64)
        .bind(req_blob)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Attach (or replace) the response on an existing history row.
    pub async fn attach_response(
        &self,
        id: Uuid,
        resp: &HttpResponse,
    ) -> anyhow::Result<()> {
        let resp_blob = serde_json::to_vec(resp)?;
        sqlx::query(
            "UPDATE history SET status = ?, response_length = ?, mime = ?,
                response_blob = ?, elapsed_ms = ? WHERE id = ?",
        )
        .bind(resp.status as i64)
        .bind(resp.body.len() as i64)
        .bind(resp.header("Content-Type"))
        .bind(resp_blob)
        .bind(resp.elapsed_ms.map(|x| x as i64))
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM history WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn clear(&self) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM history").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn set_comment(&self, id: Uuid, comment: Option<&str>) -> anyhow::Result<()> {
        sqlx::query("UPDATE history SET comment = ? WHERE id = ?")
            .bind(comment)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_color(&self, id: Uuid, color: Option<&str>) -> anyhow::Result<()> {
        sqlx::query("UPDATE history SET color = ? WHERE id = ?")
            .bind(color)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn count(&self) -> anyhow::Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM history")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get::<i64, _>("n")?)
    }

    pub async fn list(&self, filter: &HistoryFilter) -> anyhow::Result<Vec<HistoryRecord>> {
        let mut sql = String::from("SELECT * FROM history WHERE 1=1");
        let mut binds: Vec<String> = Vec::new();
        if let Some(host) = &filter.host {
            sql.push_str(" AND host LIKE ?");
            binds.push(format!("%{host}%"));
        }
        if let Some(method) = &filter.method {
            sql.push_str(" AND method = ?");
            binds.push(method.clone());
        }
        if let Some(status) = filter.status {
            sql.push_str(" AND status = ?");
            binds.push(status.to_string());
        }
        if let Some(search) = &filter.search {
            sql.push_str(" AND (path LIKE ? OR host LIKE ?)");
            binds.push(format!("%{search}%"));
            binds.push(format!("%{search}%"));
        }
        if filter.only_in_scope {
            sql.push_str(" AND in_scope = 1");
        }
        sql.push_str(" ORDER BY captured_at DESC");
        if let Some(limit) = filter.limit {
            sql.push_str(&format!(" LIMIT {limit}"));
        }
        if let Some(offset) = filter.offset {
            sql.push_str(&format!(" OFFSET {offset}"));
        }
        let mut q = sqlx::query(&sql);
        for b in binds {
            q = q.bind(b);
        }
        let rows = q.fetch_all(&self.pool).await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(record_from_row(&r)?);
        }
        Ok(out)
    }

    pub async fn get(&self, id: Uuid) -> anyhow::Result<Option<HistoryRecord>> {
        let row = sqlx::query("SELECT * FROM history WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(record_from_row(&r)?)),
            None => Ok(None),
        }
    }
}

fn record_from_row(row: &sqlx::sqlite::SqliteRow) -> anyhow::Result<HistoryRecord> {
    let id_str: String = row.try_get("id")?;
    let req_blob: Vec<u8> = row.try_get("request_blob")?;
    let resp_blob: Option<Vec<u8>> = row.try_get("response_blob")?;
    let request: HttpRequest = serde_json::from_slice(&req_blob)?;
    let response: Option<HttpResponse> = match resp_blob {
        Some(b) if !b.is_empty() => Some(serde_json::from_slice(&b)?),
        _ => None,
    };
    Ok(HistoryRecord {
        id: Uuid::parse_str(&id_str)?,
        captured_at: row.try_get("captured_at")?,
        host: row.try_get("host")?,
        port: row.try_get::<i64, _>("port")? as u16,
        scheme: row.try_get("scheme")?,
        method: row.try_get("method")?,
        path: row.try_get("path")?,
        status: row.try_get("status")?,
        response_length: row.try_get("response_length")?,
        mime: row.try_get("mime")?,
        tool_generated: row.try_get::<i64, _>("tool_generated")? != 0,
        color: row.try_get("color")?,
        comment: row.try_get("comment")?,
        in_scope: row.try_get::<i64, _>("in_scope")? != 0,
        elapsed_ms: row.try_get("elapsed_ms")?,
        request,
        response,
    })
}
