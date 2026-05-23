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
        if let Some(list) = self.preset_allowed_ids() {
            if !list.contains(&id) {
                return false;
            }
        }
        match &self.enabled_checks {
            Some(list) => list.iter().any(|e| e == id),
            None => true,
        }
    }

    /// For presets that map to a fixed check subset, return the allow-list.
    /// `None` means "no preset filtering, use the user's enabled_checks".
    fn preset_allowed_ids(&self) -> Option<&'static [&'static str]> {
        match self.preset {
            ScanPreset::OwaspTop10 => Some(&[
                "passive.security_headers",
                "passive.cookie_flags",
                "passive.info_disclosure",
                "active.sqli",
                "active.xss",
                "active.traversal",
                "active.cmd_injection",
                "active.ssti",
                "active.ssrf",
                "active.xxe",
                "active.deserialization",
                "active.jwt",
                "active.open_redirect",
                "active.cors",
                "active.host_header",
            ]),
            ScanPreset::Lightweight => Some(&[
                "passive.security_headers",
                "passive.cookie_flags",
                "passive.info_disclosure",
                "passive.software_disclosure",
                "active.open_redirect",
                "active.crlf",
            ]),
            ScanPreset::AuditOnly => Some(&[
                "active.sqli",
                "active.xss",
                "active.traversal",
                "active.cmd_injection",
                "active.ssti",
                "active.ssrf",
                "active.xxe",
                "active.jwt",
                "active.cors",
            ]),
            _ => None,
        }
    }
}
