//! Flow grapher — build a navigation graph from the proxy request log.
//!
//! Nodes are `host + path` endpoints (query stripped); edges are inferred from
//! the `Referer` header (referer → current) and fall back to the temporal order
//! of same-host requests. The GUI renders the resulting node/edge set.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// One row of proxy history, reduced to what the grapher needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEntry {
    pub host: String,
    pub path: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub referer: Option<String>,
    #[serde(default)]
    pub status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowNode {
    pub id: String,
    pub label: String,
    pub host: String,
    pub path: String,
    pub methods: Vec<String>,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEdge {
    pub from: String,
    pub to: String,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowGraph {
    pub nodes: Vec<FlowNode>,
    pub edges: Vec<FlowEdge>,
}

fn strip_query(p: &str) -> &str {
    p.split(['?', '#']).next().unwrap_or(p)
}

/// `host|path` key for a node.
fn key(host: &str, path: &str) -> String {
    format!("{host}|{}", strip_query(path))
}

/// Extract host+path from a referer URL.
fn referer_key(referer: &str) -> Option<String> {
    let no_scheme = referer.split("://").nth(1).unwrap_or(referer);
    let mut parts = no_scheme.splitn(2, '/');
    let host = parts.next()?.to_string();
    let path = parts.next().map(|p| format!("/{p}")).unwrap_or_else(|| "/".to_string());
    if host.is_empty() { None } else { Some(key(&host, &path)) }
}

pub fn build_flow_graph(entries: &[FlowEntry]) -> FlowGraph {
    let mut nodes: HashMap<String, FlowNode> = HashMap::new();
    let mut edges: HashMap<(String, String), u32> = HashMap::new();

    let mut last_by_host: HashMap<String, String> = HashMap::new();

    for e in entries {
        let path = strip_query(&e.path).to_string();
        let id = key(&e.host, &path);
        let node = nodes.entry(id.clone()).or_insert_with(|| FlowNode {
            id: id.clone(),
            label: if path.is_empty() || path == "/" { format!("{}/", e.host) } else { path.clone() },
            host: e.host.clone(),
            path: path.clone(),
            methods: Vec::new(),
            count: 0,
        });
        node.count += 1;
        if !e.method.is_empty() && !node.methods.contains(&e.method) {
            node.methods.push(e.method.clone());
        }

        // Edge from the Referer, if it resolves to a node we can key.
        if let Some(ref_id) = e.referer.as_deref().and_then(referer_key) {
            if ref_id != id {
                *edges.entry((ref_id, id.clone())).or_insert(0) += 1;
            }
        } else if let Some(prev) = last_by_host.get(&e.host) {
            // Fallback: temporal sequence within the same host.
            if prev != &id {
                *edges.entry((prev.clone(), id.clone())).or_insert(0) += 1;
            }
        }
        last_by_host.insert(e.host.clone(), id);
    }

    // Ensure both endpoints of every edge exist as nodes.
    for (from, to) in edges.keys() {
        for k in [from, to] {
            nodes.entry(k.clone()).or_insert_with(|| {
                let (host, path) = k.split_once('|').unwrap_or((k.as_str(), "/"));
                FlowNode {
                    id: k.clone(),
                    label: path.to_string(),
                    host: host.to_string(),
                    path: path.to_string(),
                    methods: Vec::new(),
                    count: 0,
                }
            });
        }
    }

    let mut node_vec: Vec<FlowNode> = nodes.into_values().collect();
    node_vec.sort_by(|a, b| b.count.cmp(&a.count).then(a.id.cmp(&b.id)));
    let edge_vec: Vec<FlowEdge> = edges
        .into_iter()
        .map(|((from, to), count)| FlowEdge { from, to, count })
        .collect();

    FlowGraph { nodes: node_vec, edges: edge_vec }
}
