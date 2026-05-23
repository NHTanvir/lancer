//! Param Miner — hidden parameter discovery via response-fingerprint
//! deviation.
//!
//! Strategy: bucket-fuzz a wordlist of candidate parameter names against the
//! target endpoint. We add `?candidate=lancerprobe` (or extra body fields) one
//! at a time, compare the resulting response status / length / body shape
//! against a baseline. A meaningful deviation flags the candidate as a
//! probably-accepted parameter.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use lancer_core::HttpRequest;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::client::HttpClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamHit {
    pub name: String,
    pub baseline_status: u16,
    pub status: u16,
    pub baseline_length: usize,
    pub length: usize,
    pub reflected: bool,
}

pub const COMMON_NAMES: &[&str] = &[
    "id", "user", "userid", "uid", "username", "name", "email", "auth", "token", "session",
    "callback", "redirect", "url", "next", "return", "ref", "code", "ticket",
    "debug", "test", "verbose", "trace", "admin", "is_admin", "role", "permissions",
    "lang", "locale", "format", "type", "page", "limit", "offset", "sort", "order",
    "search", "q", "query", "filter", "fields", "include", "expand", "view",
    "secret", "key", "api_key", "apikey", "access_token", "refresh_token",
    "file", "filename", "path", "dir", "directory", "src", "dst",
];

pub async fn mine(client: HttpClient, base: HttpRequest, concurrency: usize) -> Result<Vec<ParamHit>> {
    let probe = "L4NCERPRM_88c2";
    let baseline = client.send(&base).await?;
    let bstatus = baseline.status;
    let blen = baseline.body.len();
    let bbody = baseline.body_text().unwrap_or("").to_string();

    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::new();
    for name in COMMON_NAMES {
        let permit = sem.clone().acquire_owned().await?;
        let client = client.clone();
        let base = base.clone();
        let name = (*name).to_string();
        let bbody = bbody.clone();
        handles.push(tokio::spawn(async move {
            let _p = permit;
            let mut req = base.clone();
            let sep = if req.path.contains('?') { "&" } else { "?" };
            req.path = format!("{}{sep}{name}={probe}", req.path);
            tokio::time::sleep(Duration::from_millis(15)).await;
            let Ok(resp) = client.send(&req).await else { return None };
            let body = resp.body_text().unwrap_or("");
            let status_changed = resp.status != bstatus;
            let len_changed = (resp.body.len() as i64 - blen as i64).abs() > 64;
            let reflected = body.contains(probe);
            let body_shape_changed = body.len() != bbody.len()
                && (body != bbody);
            if reflected || status_changed || (len_changed && body_shape_changed) {
                Some(ParamHit {
                    name,
                    baseline_status: bstatus,
                    status: resp.status,
                    baseline_length: blen,
                    length: resp.body.len(),
                    reflected,
                })
            } else {
                None
            }
        }));
    }
    let mut out = Vec::new();
    for h in handles {
        if let Ok(Some(hit)) = h.await {
            out.push(hit);
        }
    }
    Ok(out)
}
