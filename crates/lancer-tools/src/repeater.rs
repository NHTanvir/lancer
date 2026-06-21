//! Repeater — manual request resender with tabs, groups, notes, and a per-tab
//! send history.

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

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RepeaterTab {
    pub id: Uuid,
    pub title: String,
    pub notes: String,
    pub group_id: Option<Uuid>,
    pub history: Vec<RepeaterEntry>,
    pub follow_redirects: bool,
    pub update_content_length: bool,
    pub use_cookie_jar: bool,
    /// Optional script (Bambda-equivalent) applied to the request before send.
    pub pre_send_script: Option<String>,
}

impl RepeaterTab {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            notes: String::new(),
            group_id: None,
            history: Vec::new(),
            follow_redirects: false,
            update_content_length: true,
            use_cookie_jar: false,
            pre_send_script: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepeaterGroup {
    pub id: Uuid,
    pub name: String,
    pub tab_ids: Vec<Uuid>,
}

impl RepeaterGroup {
    pub fn new(name: impl Into<String>) -> Self {
        Self { id: Uuid::new_v4(), name: name.into(), tab_ids: Vec::new() }
    }
}

#[derive(Clone)]
pub struct Repeater {
    pub client: HttpClient,
    pub tabs: Arc<RwLock<Vec<RepeaterTab>>>,
    pub groups: Arc<RwLock<Vec<RepeaterGroup>>>,
}

impl Repeater {
    pub fn new(client: HttpClient) -> Self {
        Self {
            client,
            tabs: Arc::new(RwLock::new(Vec::new())),
            groups: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn create_tab(&self, title: impl Into<String>) -> Uuid {
        let tab = RepeaterTab::new(title);
        let id = tab.id;
        self.tabs.write().push(tab);
        id
    }

    pub fn create_group(&self, name: impl Into<String>) -> Uuid {
        let g = RepeaterGroup::new(name);
        let id = g.id;
        self.groups.write().push(g);
        id
    }

    pub fn add_tab_to_group(&self, tab_id: Uuid, group_id: Uuid) {
        if let Some(g) = self.groups.write().iter_mut().find(|g| g.id == group_id) {
            if !g.tab_ids.contains(&tab_id) {
                g.tab_ids.push(tab_id);
            }
        }
        if let Some(t) = self.tabs.write().iter_mut().find(|t| t.id == tab_id) {
            t.group_id = Some(group_id);
        }
    }

    pub async fn send(&self, tab_id: Uuid, mut req: HttpRequest) -> Result<HttpResponse> {
        if let Some(tab) = self.tabs.read().iter().find(|t| t.id == tab_id) {
            if tab.update_content_length && !req.body.is_empty() {
                req.set_header("Content-Length", req.body.len().to_string());
            }
        }
        let mut resp = self.client.send(&req).await?;
        // Follow up to 5 redirects when configured.
        let follow = self
            .tabs
            .read()
            .iter()
            .find(|t| t.id == tab_id)
            .map(|t| t.follow_redirects)
            .unwrap_or(false);
        if follow {
            let mut hops = 0;
            while matches!(resp.status, 301 | 302 | 303 | 307 | 308) && hops < 5 {
                hops += 1;
                let Some(loc) = resp.header("Location") else { break };
                let target = match url::Url::parse(loc) {
                    Ok(u) => u,
                    Err(_) => {
                        let base = format!("{}://{}", req.meta.scheme, req.meta.host);
                        match url::Url::parse(&base).and_then(|b| b.join(loc)) {
                            Ok(u) => u,
                            Err(_) => break,
                        }
                    }
                };
                // 307/308 MUST preserve the original method AND body; 301/302/303
                // are coerced to a body-less GET (conventional browser behavior).
                let preserve = matches!(resp.status, 307 | 308);
                let method = if preserve { req.method.as_str() } else { "GET" };
                let mut next = HttpRequest::builder(method, target.as_str())?;
                for h in &req.headers {
                    if h.name.eq_ignore_ascii_case("host") || h.name.eq_ignore_ascii_case("content-length") {
                        continue;
                    }
                    next.set_header(&h.name, h.value.clone());
                }
                if preserve {
                    next.body = req.body.clone();
                    if !next.body.is_empty() {
                        next.set_header("Content-Length", next.body.len().to_string());
                    }
                }
                resp = self.client.send(&next).await?;
                req = next;
            }
        }
        if let Some(tab) = self.tabs.write().iter_mut().find(|t| t.id == tab_id) {
            tab.history.push(RepeaterEntry {
                sent_at: Utc::now(),
                request: req,
                response: Some(resp.clone()),
            });
        }
        Ok(resp)
    }

    /// Send each tab in a group, in order. Returns each response.
    pub async fn send_group(
        &self,
        group_id: Uuid,
        request_for_tab: impl Fn(&RepeaterTab) -> HttpRequest,
    ) -> Result<Vec<HttpResponse>> {
        let tab_ids: Vec<Uuid> = self
            .groups
            .read()
            .iter()
            .find(|g| g.id == group_id)
            .map(|g| g.tab_ids.clone())
            .unwrap_or_default();
        let mut out = Vec::with_capacity(tab_ids.len());
        for id in tab_ids {
            let req = {
                let tabs = self.tabs.read();
                let Some(tab) = tabs.iter().find(|t| t.id == id) else { continue };
                request_for_tab(tab)
            };
            let resp = self.send(id, req).await?;
            out.push(resp);
        }
        Ok(out)
    }
}

/// Pretty-print a JSON or XML body for the UI's "copy as pretty" action.
pub fn pretty_body(content_type: &str, body: &[u8]) -> String {
    if content_type.contains("json") {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
            return serde_json::to_string_pretty(&v).unwrap_or_else(|_| {
                String::from_utf8_lossy(body).into_owned()
            });
        }
    }
    if content_type.contains("xml") {
        return pretty_xml(body);
    }
    String::from_utf8_lossy(body).into_owned()
}

fn pretty_xml(body: &[u8]) -> String {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;
    use quick_xml::writer::Writer;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(e) => {
                if writer.write_event(e).is_err() {
                    return String::from_utf8_lossy(body).into_owned();
                }
            }
            Err(_) => return String::from_utf8_lossy(body).into_owned(),
        }
        buf.clear();
    }
    String::from_utf8_lossy(&writer.into_inner()).into_owned()
}
