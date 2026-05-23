//! Repeater stub. Real implementation lands in commit 2.

use std::sync::Arc;

use anyhow::Result;
use chrono::{DateTime, Utc};
use lancer_core::{HttpRequest, HttpResponse};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::client::HttpClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepeaterEntry {
    pub sent_at: DateTime<Utc>,
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RepeaterTab {
    pub id: Uuid,
    pub title: String,
    pub notes: String,
    pub history: Vec<RepeaterEntry>,
    pub follow_redirects: bool,
    pub update_content_length: bool,
}

impl RepeaterTab {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            notes: String::new(),
            history: Vec::new(),
            follow_redirects: false,
            update_content_length: true,
        }
    }
}

#[derive(Clone)]
pub struct Repeater {
    pub client: HttpClient,
    pub tabs: Arc<RwLock<Vec<RepeaterTab>>>,
}

impl Repeater {
    pub fn new(client: HttpClient) -> Self {
        Self { client, tabs: Arc::new(RwLock::new(Vec::new())) }
    }

    pub fn create_tab(&self, title: impl Into<String>) -> Uuid {
        let tab = RepeaterTab::new(title);
        let id = tab.id;
        self.tabs.write().push(tab);
        id
    }

    pub async fn send(&self, tab_id: Uuid, mut req: HttpRequest) -> Result<HttpResponse> {
        if let Some(tab) = self.tabs.read().iter().find(|t| t.id == tab_id) {
            if tab.update_content_length && !req.body.is_empty() {
                req.set_header("Content-Length", req.body.len().to_string());
            }
        }
        let resp = self.client.send(&req).await?;
        if let Some(tab) = self.tabs.write().iter_mut().find(|t| t.id == tab_id) {
            tab.history.push(RepeaterEntry {
                sent_at: Utc::now(),
                request: req,
                response: Some(resp.clone()),
            });
        }
        Ok(resp)
    }
}
