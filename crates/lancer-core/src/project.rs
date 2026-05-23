//! Project metadata: in-memory or disk-backed.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::scope::Scope;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProjectKind {
    /// In-memory only — no disk persistence.
    Temporary,
    /// Backed by a `.lancer` SQLite file.
    OnDisk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMeta {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub kind: ProjectKind,
    pub path: Option<PathBuf>,
    pub scope: Scope,
    pub schema_version: u32,
}

impl ProjectMeta {
    pub const SCHEMA_VERSION: u32 = 1;

    pub fn temporary(name: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            kind: ProjectKind::Temporary,
            path: None,
            scope: Scope::default(),
            schema_version: Self::SCHEMA_VERSION,
        }
    }

    pub fn on_disk(name: impl Into<String>, path: impl AsRef<Path>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            kind: ProjectKind::OnDisk,
            path: Some(path.as_ref().to_path_buf()),
            scope: Scope::default(),
            schema_version: Self::SCHEMA_VERSION,
        }
    }
}

/// Convenience wrapper used by callers that don't need the full storage layer.
#[derive(Debug, Clone)]
pub struct Project {
    pub meta: ProjectMeta,
}

impl Project {
    pub fn new(meta: ProjectMeta) -> Self {
        Self { meta }
    }
}
