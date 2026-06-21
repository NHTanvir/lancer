//! Auto-snapshot of the project DB to a rotating sidecar file.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::time::{interval, Duration};

use crate::Storage;

/// Periodically COPY the live SQLite DB to a numbered snapshot. Keeps the
/// last `max_keep` snapshots; older ones are pruned.
pub async fn run_snapshot_loop(
    storage: Storage,
    db_path: PathBuf,
    every_minutes: u32,
    max_keep: u32,
) -> Result<()> {
    let mut ticker = interval(Duration::from_secs(every_minutes.max(1) as u64 * 60));
    loop {
        ticker.tick().await;
        if let Err(e) = take_snapshot(&storage, &db_path, max_keep).await {
            tracing::warn!("snapshot failed: {e}");
        }
    }
}

pub async fn take_snapshot(storage: &Storage, db_path: &Path, max_keep: u32) -> Result<PathBuf> {
    let ts = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let parent = db_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let snap_dir = parent.join(".lancer-snapshots");
    tokio::fs::create_dir_all(&snap_dir).await.ok();
    let dest = snap_dir.join(format!("{}-{ts}.bak", db_path.file_name().and_then(|s| s.to_str()).unwrap_or("project")));
    // Flush WAL contents into the main DB file so the plain copy is consistent.
    // TRUNCATE is best-effort: if writers are active it may not fully checkpoint,
    // but it never corrupts and we still capture all flushable committed data.
    let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(storage.pool())
        .await;
    tokio::fs::copy(db_path, &dest).await.context("copy db")?;
    prune(&snap_dir, max_keep).await.ok();
    Ok(dest)
}

async fn prune(dir: &Path, max_keep: u32) -> Result<()> {
    let mut files: Vec<_> = Vec::new();
    let mut iter = tokio::fs::read_dir(dir).await?;
    while let Ok(Some(entry)) = iter.next_entry().await {
        if entry.file_type().await?.is_file() {
            files.push((entry.path(), entry.metadata().await?.modified()?));
        }
    }
    files.sort_by_key(|(_, m)| *m);
    while files.len() > max_keep as usize {
        let (path, _) = files.remove(0);
        let _ = tokio::fs::remove_file(path).await;
    }
    Ok(())
}

/// Find the most recent snapshot for the given DB file, if any.
pub fn latest_snapshot(db_path: &Path) -> Option<PathBuf> {
    let parent = db_path.parent()?;
    let snap_dir = parent.join(".lancer-snapshots");
    let mut entries: Vec<_> = std::fs::read_dir(&snap_dir).ok()?.flatten().collect();
    entries.sort_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()));
    entries.into_iter().last().map(|e| e.path())
}
