//! Scan engine — orchestrates passive and active checks.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use lancer_core::{HttpRequest, HttpResponse};
use lancer_storage::issues::Issue;
use lancer_storage::IssueStore;
use lancer_tools::HttpClient;
use tokio::sync::Semaphore;
use tracing::{debug, info};

use crate::config::ScanConfig;
use crate::insertion::find_insertion_points;
use crate::{active, passive, ActiveCheck, PassiveCheck};

pub struct ScanEngine {
    pub config: ScanConfig,
    pub client: HttpClient,
    passive_checks: Vec<Arc<dyn PassiveCheck>>,
    active_checks: Vec<Arc<dyn ActiveCheck>>,
    pub issue_store: Option<IssueStore>,
}

impl ScanEngine {
    pub fn new(config: ScanConfig, client: HttpClient, issue_store: Option<IssueStore>) -> Self {
        Self {
            config,
            client,
            passive_checks: passive::registry(),
            active_checks: active::registry(),
            issue_store,
        }
    }

    pub async fn run_passive(&self, req: &HttpRequest, resp: &HttpResponse) -> Vec<Issue> {
        if !self.config.preset.passive_enabled() {
            return Vec::new();
        }
        let mut all = Vec::new();
        for ck in &self.passive_checks {
            if !self.config.check_enabled(ck.id()) {
                continue;
            }
            let mut found = ck.check(req, resp).await;
            for i in &mut found {
                i.check_id = Some(ck.id().to_string());
            }
            all.extend(found);
        }
        self.persist(&all).await;
        all
    }

    pub async fn run_active(&self, base: &HttpRequest) -> Result<Vec<Issue>> {
        if !self.config.preset.active_enabled() {
            return Ok(Vec::new());
        }
        let points = find_insertion_points(base);
        if points.is_empty() {
            return Ok(Vec::new());
        }
        info!(host = %base.meta.host, points = points.len(), "starting active scan");
        let sem = Arc::new(Semaphore::new(self.config.max_concurrency_per_host.max(1)));
        let mut handles = Vec::new();
        for point in points {
            for ck in &self.active_checks {
                if !self.config.check_enabled(ck.id()) {
                    continue;
                }
                let permit = sem.clone().acquire_owned().await?;
                let client = self.client.clone();
                let base = base.clone();
                let point = point.clone();
                let ck = ck.clone();
                let throttle = self.config.throttle_ms;
                handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    if throttle > 0 {
                        tokio::time::sleep(Duration::from_millis(throttle)).await;
                    }
                    ck.run(&client, &base, &point).await
                }));
            }
        }
        let mut out = Vec::new();
        for h in handles {
            match h.await {
                Ok(found) => out.extend(found),
                Err(e) => debug!("active task failed: {e}"),
            }
        }
        self.persist(&out).await;
        Ok(out)
    }

    async fn persist(&self, issues: &[Issue]) {
        if let Some(store) = &self.issue_store {
            for i in issues {
                if let Err(e) = store.insert(i).await {
                    debug!("issue insert failed: {e}");
                }
            }
        }
    }
}
