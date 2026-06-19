//! SQLite-backed persistence for Lancer projects.
//!
//! A Lancer project file is a single `.lancer` SQLite database that holds:
//! - project metadata (id, name, scope, settings)
//! - HTTP history (request + response pairs)
//! - WebSocket history
//! - Scanner issues
//! - Saved Repeater tabs
//! - Saved Intruder attacks
//! - Saved Comparer items
//! - Organizer entries
//! - Configuration library (named scan/intruder/session configs)

pub mod history;
pub mod issues;
pub mod migrations;
pub mod organizer;
pub mod project;
pub mod snapshot;
pub mod websocket;

use std::path::Path;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use tracing::info;

pub use history::{HistoryFilter, HistoryRecord, HistoryStore};
pub use issues::{Issue, IssueStore};
pub use organizer::{OrganizerEntry, OrganizerStore};
pub use project::ProjectStore;
pub use websocket::{WsMessage, WsStore};

/// Top-level storage handle. Wraps a connection pool to a single project DB.
#[derive(Debug, Clone)]
pub struct Storage {
    pool: SqlitePool,
}

impl Storage {
    /// Open or create an on-disk project file.
    pub async fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await.ok();
            }
        }
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .busy_timeout(std::time::Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;
        info!(?path, "opened project storage");
        let store = Self { pool };
        migrations::apply(&store).await?;
        Ok(store)
    }

    /// Open an ephemeral temporary project (`ProjectKind::Temporary`).
    ///
    /// Backed by a throwaway file in the OS temp dir rather than a private
    /// SQLite `:memory:` database. A `:memory:` DB is bound to its single
    /// connection: if the pool ever recycles that connection (idle reap, health
    /// check, or error) the database — tables *and* applied migrations — is
    /// silently recreated empty, surfacing later as "no such table: history"
    /// and 500ing every read once the app has sat idle. A temp file survives
    /// connection recycling, so the data persists for the whole process while
    /// still being ephemeral (a fresh unique file per run, never reopened).
    pub async fn in_memory() -> anyhow::Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join("lancer-temp");
        tokio::fs::create_dir_all(&dir).await.ok();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!(
            "temp-{}-{}-{}.lancer",
            std::process::id(),
            nanos,
            seq
        ));
        // `open` creates the file, enables WAL, and runs migrations.
        Self::open(&path).await
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub fn history(&self) -> HistoryStore {
        HistoryStore::new(self.pool.clone())
    }

    pub fn issues(&self) -> IssueStore {
        IssueStore::new(self.pool.clone())
    }

    pub fn organizer(&self) -> OrganizerStore {
        OrganizerStore::new(self.pool.clone())
    }

    pub fn websockets(&self) -> WsStore {
        WsStore::new(self.pool.clone())
    }

    pub fn project_store(&self) -> ProjectStore {
        ProjectStore::new(self.pool.clone())
    }
}
