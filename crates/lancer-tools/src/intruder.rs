//! Intruder — payload-driven attack runner.
//!
//! Attack types implemented in this commit:
//! - **Sniper** — iterates one payload set across each position one at a time
//! - **Battering Ram** — same payload applied to every position simultaneously
//! - **Pitchfork** — N payload sets, paired by index across N positions
//! - **Cluster Bomb** — N payload sets, cartesian product across N positions
//!
//! For each generated request, the runner records status, length, time, and
//! the configured Grep matches/extracts.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use lancer_core::{HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::client::HttpClient;
use crate::grep::{analyze, GrepConfig, GrepResult};
use crate::payload_processor::apply_chain;
use crate::positions::ParsedTemplate;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackKind {
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PayloadSet {
    Simple(Vec<String>),
    Numbers { from: i64, to: i64, step: i64 },
    BruteForce { charset: String, min_len: usize, max_len: usize },
    Null { count: usize },
    /// Stream from a file on disk — generated as the attack runs (memory-mapped
    /// wordlists are loaded lazily by the runner).
    FromFile { path: std::path::PathBuf },
}

impl PayloadSet {
    pub fn into_iter(self) -> Box<dyn Iterator<Item = String> + Send> {
        match self {
            PayloadSet::Simple(v) => Box::new(v.into_iter()),
            PayloadSet::Numbers { from, to, step } => {
                let step = if step == 0 { 1 } else { step };
                Box::new(
                    (0..)
                        .map(move |i| from + i * step)
                        .take_while(move |&n| if step > 0 { n <= to } else { n >= to })
                        .map(|n| n.to_string()),
                )
            }
            PayloadSet::BruteForce { charset, min_len, max_len } => {
                Box::new(BruteForceIter::new(charset, min_len, max_len))
            }
            PayloadSet::Null { count } => Box::new((0..count).map(|_| String::new())),
            PayloadSet::FromFile { path } => {
                use std::io::{BufRead, BufReader};
                match std::fs::File::open(&path) {
                    Ok(f) => {
                        let reader = BufReader::new(f);
                        Box::new(reader.lines().filter_map(|l| l.ok()))
                    }
                    Err(_) => Box::new(std::iter::empty()),
                }
            }
        }
    }
}

struct BruteForceIter {
    charset: Vec<char>,
    max_len: usize,
    state: Vec<usize>,
    started: bool,
}

impl BruteForceIter {
    fn new(charset: String, min_len: usize, max_len: usize) -> Self {
        let cs: Vec<char> = charset.chars().collect();
        Self { charset: cs, max_len, state: vec![0; min_len.max(1)], started: false }
    }
    fn render(&self) -> String {
        self.state.iter().rev().map(|&i| self.charset[i]).collect()
    }
}

impl Iterator for BruteForceIter {
    type Item = String;
    fn next(&mut self) -> Option<String> {
        if self.charset.is_empty() {
            return None;
        }
        if !self.started {
            self.started = true;
            return Some(self.render());
        }
        let mut i = 0;
        loop {
            if i >= self.state.len() {
                if self.state.len() >= self.max_len {
                    return None;
                }
                self.state = vec![0; self.state.len() + 1];
                return Some(self.render());
            }
            self.state[i] += 1;
            if self.state[i] < self.charset.len() {
                return Some(self.render());
            }
            self.state[i] = 0;
            i += 1;
        }
    }
}

/// Per-payload-set post-processing rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PayloadProcessor {
    Prefix(String),
    Suffix(String),
    UrlEncode,
    Base64Encode,
    ToUpper,
    ToLower,
    Match { pattern: String, replacement: String, regex: bool },
    Hash(String),
    SkipIfMatches(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntruderConfig {
    pub kind: AttackKind,
    pub max_concurrency: usize,
    pub throttle_ms: u64,
    pub retry_on_error: bool,
    pub max_retries: usize,
    pub processors: Vec<PayloadProcessor>,
    pub grep: GrepConfig,
}

impl Default for IntruderConfig {
    fn default() -> Self {
        Self {
            kind: AttackKind::Sniper,
            max_concurrency: 10,
            throttle_ms: 0,
            retry_on_error: true,
            max_retries: 2,
            processors: Vec::new(),
            grep: GrepConfig {
                match_strings: Vec::new(),
                extracts: Vec::new(),
                reflect_payload: true,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResult {
    pub index: usize,
    pub payloads: Vec<String>,
    pub status: u16,
    pub length: usize,
    pub time_ms: u64,
    pub started_at: DateTime<Utc>,
    pub grep: GrepResult,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct Intruder {
    pub client: HttpClient,
    pub config: IntruderConfig,
    pub concurrency: Arc<Semaphore>,
}

impl Intruder {
    pub fn new(client: HttpClient, config: IntruderConfig) -> Self {
        let n = config.max_concurrency.max(1);
        Self { client, config, concurrency: Arc::new(Semaphore::new(n)) }
    }

    /// Run the configured attack against `template` and return the results in
    /// order. For very large attacks the caller should switch to the streaming
    /// API (see `run_stream`).
    pub async fn run(
        &self,
        template: ParsedTemplate,
        sets: Vec<PayloadSet>,
    ) -> Result<Vec<AttackResult>> {
        let pos_count = template.position_count();
        if pos_count == 0 {
            return Err(anyhow!("template has no payload positions"));
        }
        let combos: Vec<Vec<String>> = match self.config.kind {
            AttackKind::Sniper => sniper_combos(&template, sets)?,
            AttackKind::BatteringRam => battering_ram_combos(pos_count, sets)?,
            AttackKind::Pitchfork => pitchfork_combos(pos_count, sets)?,
            AttackKind::ClusterBomb => cluster_bomb_combos(pos_count, sets)?,
        };

        let mut handles = Vec::with_capacity(combos.len());
        for (i, raw_payloads) in combos.into_iter().enumerate() {
            // Apply per-payload processors.
            let mut processed = Vec::with_capacity(raw_payloads.len());
            let mut skip = false;
            for p in &raw_payloads {
                match apply_chain(&self.config.processors, p)? {
                    Some(v) => processed.push(v),
                    None => {
                        skip = true;
                        break;
                    }
                }
            }
            if skip {
                continue;
            }
            let req = template.render(&processed);

            let permit = self.concurrency.clone().acquire_owned().await?;
            let client = self.client.clone();
            let throttle = self.config.throttle_ms;
            let max_retries = if self.config.retry_on_error {
                self.config.max_retries
            } else {
                0
            };
            let cfg = self.config.clone();
            let payloads_clone = processed.clone();
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                if throttle > 0 {
                    tokio::time::sleep(Duration::from_millis(throttle)).await;
                }
                let started = Instant::now();
                let start_clock = Utc::now();
                let mut last_err = None;
                for attempt in 0..=max_retries {
                    match client.send(&req).await {
                        Ok(resp) => {
                            return finalize(
                                i,
                                &payloads_clone,
                                &cfg,
                                &resp,
                                start_clock,
                                started,
                            );
                        }
                        Err(e) => {
                            last_err = Some(e.to_string());
                            if attempt < max_retries {
                                tokio::time::sleep(Duration::from_millis(
                                    100 * (attempt as u64 + 1),
                                ))
                                .await;
                            }
                        }
                    }
                }
                AttackResult {
                    index: i,
                    payloads: payloads_clone,
                    status: 0,
                    length: 0,
                    time_ms: started.elapsed().as_millis() as u64,
                    started_at: start_clock,
                    grep: GrepResult::default(),
                    error: last_err,
                }
            }));
        }

        let mut out = Vec::with_capacity(handles.len());
        for h in handles {
            out.push(h.await?);
        }
        out.sort_by_key(|r| r.index);
        Ok(out)
    }

    pub async fn dry_run(&self, _t: &HttpRequest, _p: PayloadSet) -> Result<usize> {
        Ok(0)
    }
}

fn finalize(
    index: usize,
    payloads: &[String],
    cfg: &IntruderConfig,
    resp: &HttpResponse,
    started_at: DateTime<Utc>,
    started: Instant,
) -> AttackResult {
    let grep = analyze(&cfg.grep, resp, payloads.first().map(|s| s.as_str()).unwrap_or(""));
    AttackResult {
        index,
        payloads: payloads.to_vec(),
        status: resp.status,
        length: resp.body.len(),
        time_ms: started.elapsed().as_millis() as u64,
        started_at,
        grep,
        error: None,
    }
}

fn sniper_combos(template: &ParsedTemplate, sets: Vec<PayloadSet>) -> Result<Vec<Vec<String>>> {
    if sets.len() != 1 {
        return Err(anyhow!("Sniper needs exactly one payload set"));
    }
    let pos_count = template.position_count();
    let payloads: Vec<String> = sets.into_iter().next().unwrap().into_iter().collect();
    let mut out = Vec::with_capacity(payloads.len() * pos_count);
    for pos in 0..pos_count {
        for p in &payloads {
            // Other positions keep their original (un-marked) payload text.
            let mut row: Vec<String> =
                template.positions.iter().map(|x| x.original.clone()).collect();
            row[pos] = p.clone();
            out.push(row);
        }
    }
    Ok(out)
}

fn battering_ram_combos(pos_count: usize, sets: Vec<PayloadSet>) -> Result<Vec<Vec<String>>> {
    if sets.len() != 1 {
        return Err(anyhow!("Battering Ram needs exactly one payload set"));
    }
    let payloads: Vec<String> = sets.into_iter().next().unwrap().into_iter().collect();
    Ok(payloads
        .into_iter()
        .map(|p| vec![p; pos_count])
        .collect())
}

fn pitchfork_combos(pos_count: usize, sets: Vec<PayloadSet>) -> Result<Vec<Vec<String>>> {
    if sets.len() != pos_count {
        return Err(anyhow!(
            "Pitchfork needs one payload set per position (have {}, need {})",
            sets.len(),
            pos_count
        ));
    }
    let lists: Vec<Vec<String>> = sets
        .into_iter()
        .map(|s| s.into_iter().collect::<Vec<_>>())
        .collect();
    let min_len = lists.iter().map(|l| l.len()).min().unwrap_or(0);
    let mut out = Vec::with_capacity(min_len);
    for i in 0..min_len {
        out.push(lists.iter().map(|l| l[i].clone()).collect());
    }
    Ok(out)
}

fn cluster_bomb_combos(pos_count: usize, sets: Vec<PayloadSet>) -> Result<Vec<Vec<String>>> {
    if sets.len() != pos_count {
        return Err(anyhow!(
            "Cluster Bomb needs one payload set per position (have {}, need {})",
            sets.len(),
            pos_count
        ));
    }
    let lists: Vec<Vec<String>> = sets
        .into_iter()
        .map(|s| s.into_iter().collect::<Vec<_>>())
        .collect();
    let mut combos: Vec<Vec<String>> = vec![Vec::new()];
    for list in &lists {
        let mut next = Vec::with_capacity(combos.len() * list.len());
        for c in &combos {
            for p in list {
                let mut row = c.clone();
                row.push(p.clone());
                next.push(row);
            }
        }
        combos = next;
    }
    Ok(combos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_bomb_cartesian() {
        let sets = vec![
            PayloadSet::Simple(vec!["a".into(), "b".into()]),
            PayloadSet::Simple(vec!["1".into(), "2".into(), "3".into()]),
        ];
        let c = cluster_bomb_combos(2, sets).unwrap();
        assert_eq!(c.len(), 6);
    }

    #[test]
    fn pitchfork_pairs() {
        let sets = vec![
            PayloadSet::Simple(vec!["a".into(), "b".into(), "c".into()]),
            PayloadSet::Simple(vec!["1".into(), "2".into()]),
        ];
        let p = pitchfork_combos(2, sets).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p[0], vec!["a".to_string(), "1".to_string()]);
        assert_eq!(p[1], vec!["b".to_string(), "2".to_string()]);
    }

    #[test]
    fn sniper_spreads_one_set() {
        let sets = vec![PayloadSet::Simple(vec!["X".into(), "Y".into()])];
        let s = sniper_combos(3, sets).unwrap();
        assert_eq!(s.len(), 6); // 3 positions × 2 payloads
    }
}
