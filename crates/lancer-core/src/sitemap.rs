//! Site map — hierarchical view of `host → subdomain → path` populated from
//! captured proxy traffic, crawls, and manual adds. Keeps method indicators
//! and Inspector-detected parameter counts per leaf.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::http_msg::{HttpRequest, HttpResponse, MimeKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeKind {
    /// Fully observed: request actually sent.
    Requested,
    /// Inferred from a link/script reference, not yet fetched.
    Inferred,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointEntry {
    pub method: String,
    pub status: Option<u16>,
    pub mime: Option<MimeKind>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub param_count: usize,
    pub kind: NodeKind,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PathNode {
    pub segment: String,
    pub endpoints: Vec<EndpointEntry>,
    pub children: BTreeMap<String, PathNode>,
}

impl PathNode {
    fn insert_at(
        &mut self,
        segments: &[String],
        endpoint: EndpointEntry,
    ) {
        if segments.is_empty() {
            push_or_merge(&mut self.endpoints, endpoint);
            return;
        }
        let head = segments[0].clone();
        let entry = self
            .children
            .entry(head.clone())
            .or_insert_with(|| PathNode { segment: head, ..Default::default() });
        entry.insert_at(&segments[1..], endpoint);
    }
}

fn push_or_merge(into: &mut Vec<EndpointEntry>, e: EndpointEntry) {
    if let Some(existing) = into.iter_mut().find(|x| x.method == e.method) {
        existing.status = e.status.or(existing.status);
        existing.mime = e.mime.or(existing.mime);
        existing.last_seen = e.last_seen.max(existing.last_seen);
        existing.param_count = e.param_count.max(existing.param_count);
        if e.kind == NodeKind::Requested {
            existing.kind = NodeKind::Requested;
        }
    } else {
        into.push(e);
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HostNode {
    pub host: String,
    pub root: PathNode,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SiteMap {
    pub hosts: BTreeMap<String, HostNode>,
}

impl SiteMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_request(&mut self, req: &HttpRequest, kind: NodeKind) {
        let entry = EndpointEntry {
            method: req.method.as_str().to_string(),
            status: None,
            mime: None,
            last_seen: req.meta.captured_at,
            param_count: crate::Inspector::from_request(req).params.len(),
            kind,
        };
        self.insert_full(&req.meta.host, &req.path, entry);
    }

    pub fn record_pair(&mut self, req: &HttpRequest, resp: &HttpResponse) {
        let entry = EndpointEntry {
            method: req.method.as_str().to_string(),
            status: Some(resp.status),
            mime: Some(resp.mime()),
            last_seen: req.meta.captured_at,
            param_count: crate::Inspector::from_request(req).params.len(),
            kind: NodeKind::Requested,
        };
        self.insert_full(&req.meta.host, &req.path, entry);
    }

    pub fn record_inferred(&mut self, host: &str, path: &str) {
        let entry = EndpointEntry {
            method: "GET".to_string(),
            status: None,
            mime: None,
            last_seen: chrono::Utc::now(),
            param_count: 0,
            kind: NodeKind::Inferred,
        };
        self.insert_full(host, path, entry);
    }

    fn insert_full(&mut self, host: &str, path: &str, entry: EndpointEntry) {
        let host_node = self
            .hosts
            .entry(host.to_string())
            .or_insert_with(|| HostNode { host: host.to_string(), ..Default::default() });
        let path_only = path.split('?').next().unwrap_or(path);
        let segments: Vec<String> = path_only
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        host_node.root.insert_at(&segments, entry);
    }

    /// Flatten to a list of (host, path, endpoint) triples for table views.
    pub fn flatten(&self) -> Vec<(String, String, EndpointEntry)> {
        let mut out = Vec::new();
        for h in self.hosts.values() {
            walk(&h.host, &h.root, &mut String::new(), &mut out);
        }
        out
    }

    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    pub fn endpoint_count(&self) -> usize {
        let mut n = 0;
        for h in self.hosts.values() {
            count(&h.root, &mut n);
        }
        n
    }
}

fn walk(
    host: &str,
    node: &PathNode,
    path: &mut String,
    out: &mut Vec<(String, String, EndpointEntry)>,
) {
    for e in &node.endpoints {
        out.push((host.to_string(), if path.is_empty() { "/".into() } else { path.clone() }, e.clone()));
    }
    for (seg, child) in &node.children {
        let prev_len = path.len();
        path.push('/');
        path.push_str(seg);
        walk(host, child, path, out);
        path.truncate(prev_len);
    }
}

fn count(node: &PathNode, n: &mut usize) {
    *n += node.endpoints.len();
    for c in node.children.values() {
        count(c, n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HttpRequest;

    #[test]
    fn inserts_and_dedupes() {
        let mut sm = SiteMap::new();
        let r1 = HttpRequest::builder("GET", "https://x.com/a/b").unwrap();
        sm.record_request(&r1, NodeKind::Requested);
        sm.record_inferred("x.com", "/a/b/c");
        let r2 = HttpRequest::builder("POST", "https://x.com/a/b").unwrap();
        sm.record_request(&r2, NodeKind::Requested);
        assert_eq!(sm.endpoint_count(), 3);
        let flat = sm.flatten();
        assert!(flat.iter().any(|(_h, p, e)| p == "/a/b" && e.method == "GET"));
        assert!(flat.iter().any(|(_h, p, e)| p == "/a/b" && e.method == "POST"));
        assert!(flat.iter().any(|(_h, p, e)| p == "/a/b/c" && e.kind == NodeKind::Inferred));
    }
}
