//! Higher-level Organizer helpers built on top of `lancer_storage::OrganizerStore`.

use anyhow::Result;
use lancer_core::{HttpRequest, HttpResponse};
use lancer_storage::{OrganizerEntry, OrganizerStore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct OrganizerTools {
    store: OrganizerStore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveSpec<'a> {
    pub title: &'a str,
    pub tags: Vec<String>,
    pub notes: Option<String>,
}

impl OrganizerTools {
    pub fn new(store: OrganizerStore) -> Self {
        Self { store }
    }

    pub async fn save(
        &self,
        spec: SaveSpec<'_>,
        request: HttpRequest,
        response: Option<HttpResponse>,
    ) -> Result<uuid::Uuid> {
        let entry = OrganizerEntry {
            id: uuid::Uuid::new_v4(),
            title: spec.title.to_string(),
            tags: spec.tags,
            notes: spec.notes,
            added_at: chrono::Utc::now(),
            request,
            response,
        };
        let id = entry.id;
        self.store.insert(&entry).await?;
        Ok(id)
    }

    pub async fn search(&self, query: &str) -> Result<Vec<OrganizerEntry>> {
        let all = self.store.list().await?;
        let q = query.to_lowercase();
        Ok(all
            .into_iter()
            .filter(|e| {
                e.title.to_lowercase().contains(&q)
                    || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
                    || e.notes
                        .as_deref()
                        .map(|n| n.to_lowercase().contains(&q))
                        .unwrap_or(false)
            })
            .collect())
    }

    pub async fn list_by_tag(&self, tag: &str) -> Result<Vec<OrganizerEntry>> {
        let all = self.store.list().await?;
        Ok(all
            .into_iter()
            .filter(|e| e.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)))
            .collect())
    }
}
