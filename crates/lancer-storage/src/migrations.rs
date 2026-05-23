//! Embedded schema migrations. Keep these small and append-only.

use sqlx::Executor as _;

use crate::Storage;

/// Each migration is `(version, sql)`. Applied in order. Tracked in
/// `_lancer_migrations`.
const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("../migrations/0001_init.sql")),
    (2, include_str!("../migrations/0002_issues_organizer.sql")),
    (3, include_str!("../migrations/0003_websockets.sql")),
];

pub async fn apply(store: &Storage) -> anyhow::Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS _lancer_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        )",
    )
    .execute(store.pool())
    .await?;

    for (version, sql) in MIGRATIONS {
        let already: Option<(i64,)> = sqlx::query_as(
            "SELECT version FROM _lancer_migrations WHERE version = ?",
        )
        .bind(version)
        .fetch_optional(store.pool())
        .await?;
        if already.is_some() {
            continue;
        }
        let mut tx = store.pool().begin().await?;
        tx.execute(sqlx::raw_sql(sql)).await?;
        sqlx::query("INSERT INTO _lancer_migrations(version) VALUES (?)")
            .bind(version)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        tracing::info!(version, "applied migration");
    }
    Ok(())
}
