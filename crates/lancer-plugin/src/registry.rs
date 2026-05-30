//! Plugin loading + lifecycle.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::manifest::{PluginKind, PluginManifest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedPlugin {
    pub manifest: PluginManifest,
    pub path: PathBuf,
    /// For Rhai plugins, the embedded script body.
    pub script_body: Option<String>,
    pub enabled: bool,
}

#[derive(Default, Clone)]
pub struct PluginRegistry {
    plugins: Arc<RwLock<Vec<LoadedPlugin>>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_directory(&self, root: &Path) -> Result<usize> {
        let mut count = 0;
        for entry in walkdir(root)? {
            if !entry.ends_with("plugin.toml") {
                continue;
            }
            match self.load_one(&entry) {
                Ok(_) => count += 1,
                Err(e) => warn!("failed to load plugin at {}: {e}", entry.display()),
            }
        }
        info!(count, "plugins loaded");
        Ok(count)
    }

    pub fn load_one(&self, manifest_path: &Path) -> Result<()> {
        let toml_str = std::fs::read_to_string(manifest_path)
            .with_context(|| format!("reading {}", manifest_path.display()))?;
        let manifest: PluginManifest = toml::from_str(&toml_str).context("parsing plugin.toml")?;
        let dir = manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."));
        let script_body = if manifest.kind == PluginKind::Rhai {
            let p = manifest
                .script
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Rhai plugin missing `script` field"))?;
            Some(std::fs::read_to_string(dir.join(p))?)
        } else {
            None
        };
        let plugin = LoadedPlugin {
            manifest,
            path: dir.to_path_buf(),
            script_body,
            enabled: true,
        };
        let mut list = self.plugins.write();
        list.retain(|p| p.manifest.id != plugin.manifest.id);
        list.push(plugin);
        Ok(())
    }

    pub fn list(&self) -> Vec<LoadedPlugin> {
        self.plugins.read().clone()
    }

    pub fn enable(&self, id: &str, enabled: bool) {
        let mut list = self.plugins.write();
        if let Some(p) = list.iter_mut().find(|p| p.manifest.id == id) {
            p.enabled = enabled;
        }
    }

    /// Remove a loaded plugin by id. Returns true if one was removed.
    pub fn remove(&self, id: &str) -> bool {
        let mut list = self.plugins.write();
        let before = list.len();
        list.retain(|p| p.manifest.id != id);
        list.len() != before
    }
}

fn walkdir(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    Ok(out)
}

