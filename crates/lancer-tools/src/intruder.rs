//! Intruder stubs. Real implementation lands in commit 2 / 3.

use std::sync::Arc;

use anyhow::Result;
use lancer_core::HttpRequest;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::client::HttpClient;

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

impl BruteForceIter {
    fn render(&self) -> String {
        self.state.iter().rev().map(|&i| self.charset[i]).collect()
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
        }
    }
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

    /// Placeholder hook used by tests to confirm wiring; the real run loops are
    /// implemented in commit 2/3 alongside payload-position parsing.
    pub async fn dry_run(&self, _template: &HttpRequest, _payloads: PayloadSet) -> Result<usize> {
        Ok(0)
    }
}
