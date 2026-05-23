//! Scan configuration: presets + per-check enable/disable.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanPreset {
    Lightweight,
    Balanced,
    Deep,
    AuditOnly,
    CrawlOnly,
    PassiveOnly,
    OwaspTop10,
}

impl ScanPreset {
    pub fn passive_enabled(self) -> bool {
        !matches!(self, ScanPreset::CrawlOnly)
    }
    pub fn active_enabled(self) -> bool {
        !matches!(self, ScanPreset::PassiveOnly | ScanPreset::CrawlOnly)
    }
    pub fn deep_active(self) -> bool {
        matches!(self, ScanPreset::Deep)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub preset: ScanPreset,
    pub enabled_checks: Option<Vec<String>>,
    pub disabled_checks: Vec<String>,
    pub max_concurrency_per_host: usize,
    pub throttle_ms: u64,
    pub follow_redirects_on_audit: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            preset: ScanPreset::Balanced,
            enabled_checks: None,
            disabled_checks: Vec::new(),
            max_concurrency_per_host: 8,
            throttle_ms: 0,
            follow_redirects_on_audit: true,
        }
    }
}

impl ScanConfig {
    pub fn check_enabled(&self, id: &str) -> bool {
        if self.disabled_checks.iter().any(|d| d == id) {
            return false;
        }
        match &self.enabled_checks {
            Some(list) => list.iter().any(|e| e == id),
            None => true,
        }
    }
}
