//! Persistence for the per-project metadata row.

use lancer_core::project::{ProjectKind, ProjectMeta};
use lancer_core::scope::Scope;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ProjectStore {
    pool: SqlitePool,
}

impl ProjectStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn load(&self) -> anyhow::Result<Option<ProjectMeta>> {
        let row = sqlx::query("SELECT * FROM project_meta LIMIT 1")
            .fetch_optional(&self.pool)
            .await?;
        match row {
            None => Ok(None),
            Some(r) => {
                let id_str: String = r.try_get("id")?;
                let scope_json: String = r.try_get("scope_json")?;
                let scope: Scope = serde_json::from_str(&scope_json).unwrap_or_default();
                Ok(Some(ProjectMeta {
                    id: Uuid::parse_str(&id_str)?,
                    name: r.try_get("name")?,
                    created_at: r.try_get("created_at")?,
                    updated_at: r.try_get("updated_at")?,
                    schema_version: r.try_get::<i64, _>("schema_version")? as u32,
                    kind: ProjectKind::OnDisk,
                    path: None,
                    scope,
                }))
            }
        }
    }

    pub async fn upsert(&self, meta: &ProjectMeta) -> anyhow::Result<()> {
        let scope_json = serde_json::to_string(&meta.scope)?;
        sqlx::query(
            "INSERT INTO project_meta(id, name, created_at, updated_at, schema_version, scope_json)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                updated_at = excluded.updated_at,
                schema_version = excluded.schema_version,
                scope_json = excluded.scope_json",
        )
        .bind(meta.id.to_string())
        .bind(&meta.name)
        .bind(meta.created_at)
        .bind(meta.updated_at)
        .bind(meta.schema_version as i64)
        .bind(scope_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
