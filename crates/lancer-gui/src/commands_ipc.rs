//! Tauri-invocable commands. Listed here so they can be referenced from
//! `tauri::generate_handler!` once the `tauri` feature is enabled.

#![allow(dead_code)]

use std::sync::Arc;

use crate::app::AppState;

pub async fn proxy_status(state: Arc<AppState>) -> serde_json::Value {
    serde_json::json!({ "ok": true, "ts": chrono::Utc::now() })
}

pub async fn history_list(state: Arc<AppState>, limit: i64) -> Result<serde_json::Value, String> {
    let storage = state.project.read().clone();
    let Some(storage) = storage else {
        return Err("no project open".into());
    };
    let rows = storage
        .history()
        .list(&lancer_storage::HistoryFilter { limit: Some(limit), ..Default::default() })
        .await
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "rows": rows }))
}

pub async fn repeater_send(
    state: Arc<AppState>,
    raw: String,
    scheme: String,
) -> Result<serde_json::Value, String> {
    let mut req = lancer_core::HttpRequest::parse_wire(raw.as_bytes())
        .map_err(|e| e.to_string())?;
    req.meta.scheme = scheme;
    let resp = state.client.send(&req).await.map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "status": resp.status,
        "headers": resp.headers,
        "body": resp.body_text().unwrap_or(""),
    }))
}

pub async fn scan_full(
    state: Arc<AppState>,
    url: String,
) -> Result<serde_json::Value, String> {
    use lancer_scanner::config::ScanConfig;
    use lancer_scanner::ScanEngine;
    let engine = ScanEngine::new(ScanConfig::default(), state.client.clone(), None);
    let req = lancer_core::HttpRequest::builder("GET", &url).map_err(|e| e.to_string())?;
    let resp = state.client.send(&req).await.map_err(|e| e.to_string())?;
    let mut issues = engine.run_passive(&req, &resp).await;
    issues.extend(engine.run_active(&req).await.map_err(|e| e.to_string())?);
    Ok(serde_json::json!({ "issues": issues }))
}

pub async fn report_render(
    state: Arc<AppState>,
    format: String,
) -> Result<String, String> {
    use lancer_report::{render_html, render_json, render_markdown, render_sarif, render_xml, ReportFilter, ReportMeta};
    let storage = state.project.read().clone();
    let Some(storage) = storage else {
        return Err("no project open".into());
    };
    let issues = storage.issues().list().await.map_err(|e| e.to_string())?;
    let meta = ReportMeta::new("Lancer project");
    let f = ReportFilter::default();
    Ok(match format.as_str() {
        "json" => render_json(&meta, &issues, &f),
        "markdown" | "md" => render_markdown(&meta, &issues, &f),
        "html" => render_html(&meta, &issues, &f),
        "sarif" => render_sarif(&meta, &issues, &f),
        "xml" => render_xml(&meta, &issues, &f),
        _ => return Err("unsupported format".into()),
    })
}
