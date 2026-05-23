//! Workspace and UX presets, keybinding modes, auto-snapshot config.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkspacePreset {
    BugBounty,
    Pentest,
    RedTeam,
    ApiAudit,
    MobileAudit,
}

impl WorkspacePreset {
    pub fn default_layout(self) -> &'static str {
        match self {
            WorkspacePreset::BugBounty => "history,repeater,intruder,scanner,issues",
            WorkspacePreset::Pentest => "scope,sitemap,history,repeater,scanner,issues,reports",
            WorkspacePreset::RedTeam => "scope,sitemap,history,repeater,collaborator,issues",
            WorkspacePreset::ApiAudit => "history,repeater,scanner,issues,imports",
            WorkspacePreset::MobileAudit => "history,mobile,proxy,issues",
        }
    }

    pub fn scan_preset(self) -> &'static str {
        match self {
            WorkspacePreset::BugBounty => "balanced",
            WorkspacePreset::Pentest => "deep",
            WorkspacePreset::RedTeam => "passive-only",
            WorkspacePreset::ApiAudit => "balanced",
            WorkspacePreset::MobileAudit => "passive-only",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeybindingMode {
    Default,
    Vim,
    Emacs,
    VsCode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    pub preset: WorkspacePreset,
    pub theme: String,
    pub keybindings: KeybindingMode,
    pub auto_snapshot_minutes: u32,
    pub max_snapshots: u32,
    pub per_project_hotkeys: Vec<(String, String)>,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            preset: WorkspacePreset::Pentest,
            theme: "dark".to_string(),
            keybindings: KeybindingMode::Default,
            auto_snapshot_minutes: 10,
            max_snapshots: 12,
            per_project_hotkeys: Vec::new(),
        }
    }
}
