//! Plugin manifest schema.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub author: Option<String>,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub kind: PluginKind,
    /// For `Rhai` plugins: path to the script body (relative to manifest).
    pub script: Option<String>,
    /// For `Native` plugins: path to the cdylib relative to manifest.
    pub library: Option<String>,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginKind {
    Rhai,
    Native,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    CustomColumn,
    CustomAction,
    FilterRequest,
    FilterResponse,
    PassiveCheck,
    PaletteCommand,
}
