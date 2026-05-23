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

    /// Open an ephemeral in-memory project (`ProjectKind::Temporary`).
    pub async fn in_memory() -> anyhow::Result<Self> {
        let opts = SqliteConnectOptions::new()
            .in_memory(true)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await?;
        let store = Self { pool };
        migrations::apply(&store).await?;
        Ok(store)
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
