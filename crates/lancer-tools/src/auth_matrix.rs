//! AuthMatrix — replay a set of requests as a set of identities and produce
//! a 2-D pass/fail grid.

use std::collections::BTreeMap;

use anyhow::Result;
use lancer_core::{HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::client::HttpClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub name: String,
    pub cookie: Option<String>,
    pub authorization: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixCell {
    pub status: u16,
    pub length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixResult {
    pub rows: Vec<String>, // request names
    pub identities: Vec<String>,
    pub cells: BTreeMap<String, BTreeMap<String, MatrixCell>>,
}

pub async fn run(
    client: &HttpClient,
    requests: &[(String, HttpRequest)],
    identities: &[Identity],
) -> Result<MatrixResult> {
    let mut result = MatrixResult {
        rows: requests.iter().map(|(n, _)| n.clone()).collect(),
        identities: identities.iter().map(|i| i.name.clone()).collect(),
        cells: BTreeMap::new(),
    };
    for (name, req) in requests {
        let mut row: BTreeMap<String, MatrixCell> = BTreeMap::new();
        for id in identities {
            let mut r = req.clone();
            match (&id.cookie, &id.authorization) {
                (Some(c), _) if c.is_empty() => {
                    r.remove_header("Cookie");
                    r.remove_header("Authorization");
                }
                (Some(c), _) => r.set_header("Cookie", c.clone()),
                _ => {}
            }
            if let Some(a) = &id.authorization {
                r.set_header("Authorization", a.clone());
            }
            let resp = client.send(&r).await.unwrap_or_else(|_| HttpResponse::new(0));
            row.insert(id.name.clone(), MatrixCell { status: resp.status, length: resp.body.len() });
        }
        result.cells.insert(name.clone(), row);
    }
    Ok(result)
}

/// Render the matrix as a markdown table.
pub fn to_markdown(m: &MatrixResult) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    s.push_str("| request |");
    for id in &m.identities {
        let _ = write!(s, " {id} |");
    }
    s.push('\n');
    s.push_str("|---|");
    for _ in &m.identities {
        s.push_str("---|");
    }
    s.push('\n');
    for r in &m.rows {
        let _ = write!(s, "| {r} |");
        if let Some(row) = m.cells.get(r) {
            for id in &m.identities {
                if let Some(c) = row.get(id) {
                    let _ = write!(s, " {} / {} |", c.status, c.length);
                } else {
                    s.push_str(" - |");
                }
            }
        }
        s.push('\n');
    }
    s
}
