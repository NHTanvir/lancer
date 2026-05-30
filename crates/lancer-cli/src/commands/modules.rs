//! `lancer modules` — §52 Modules system CLI parity.
//!
//! Mirrors the `/v1/modules` HTTP handlers but calls `lancer_modules` directly.
//! Module enable/disable state is persisted to a `modules.toml` (via
//! `lancer_modules::ModulesToml`) so it survives across CLI invocations, and
//! presets are persisted to a sibling `presets.json` (the in-process
//! `PresetStore` is rebuilt from it on each run).
//!
//! Subcommands:
//!   list                 — show every registered module + its persisted state
//!   enable  <id>         — turn a module On  (persisted)
//!   disable <id>         — turn a module Off (persisted)
//!   status               — show live status for all modules (JSON or table)
//!   preset save  <name>  — snapshot the current states into a named preset
//!   preset load  <name>  — apply a named preset's states (persisted)

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use lancer_modules::{
    default_modules, ModuleConfig, ModuleRegistry, ModuleState, ModulesToml, Preset, PresetStore,
};

#[derive(Debug, Args)]
pub struct ModulesArgs {
    /// Path to the modules state file (defaults to `~/.lancer/modules.toml`).
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Emit machine-readable JSON instead of a human table.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: ModulesCmd,
}

#[derive(Debug, Subcommand)]
enum ModulesCmd {
    /// List every registered module and its persisted state.
    List,
    /// Enable a module by id (sets its state to On, persisted).
    Enable {
        /// Module id (see `lancer modules list`).
        id: String,
    },
    /// Disable a module by id (sets its state to Off, persisted).
    Disable {
        /// Module id (see `lancer modules list`).
        id: String,
    },
    /// Show live status for every module.
    Status,
    /// Manage named presets (snapshots of all module states).
    #[command(subcommand)]
    Preset(PresetCmd),
}

#[derive(Debug, Subcommand)]
enum PresetCmd {
    /// Snapshot the current module states into a named preset.
    Save {
        /// Preset name.
        name: String,
    },
    /// Apply a named preset, overwriting current states (persisted).
    Load {
        /// Preset name.
        name: String,
    },
    /// List all saved presets.
    List,
}

pub async fn run(args: ModulesArgs) -> Result<()> {
    let cfg_path = resolve_config_path(args.config)?;
    let preset_path = presets_path(&cfg_path);

    // Build the registry from the built-in module set, then rehydrate persisted
    // state from modules.toml — exactly what the API does at boot, minus HTTP.
    let registry = ModuleRegistry::new();
    for m in default_modules() {
        registry.register_boxed(m);
    }
    let mut toml = ModulesToml::load(&cfg_path);
    apply_toml_to_registry(&registry, &toml);

    // Rebuild the in-memory preset store from disk so `preset list`/`load` work.
    let presets = PresetStore::new();
    for p in load_presets(&preset_path)? {
        presets.save(p);
    }

    match args.cmd {
        ModulesCmd::List => {
            let infos = registry.list();
            if args.json {
                println!("{}", serde_json::to_string_pretty(&infos)?);
            } else {
                print_module_table(&registry);
            }
        }
        ModulesCmd::Enable { id } => {
            ensure_known(&registry, &id)?;
            registry.set_state(&id, ModuleState::On);
            persist_states(&registry, &mut toml, &cfg_path)?;
            report_state(&registry, &id, args.json)?;
        }
        ModulesCmd::Disable { id } => {
            ensure_known(&registry, &id)?;
            registry.set_state(&id, ModuleState::Off);
            persist_states(&registry, &mut toml, &cfg_path)?;
            report_state(&registry, &id, args.json)?;
        }
        ModulesCmd::Status => {
            let infos = registry.list();
            if args.json {
                println!("{}", serde_json::to_string_pretty(&infos)?);
            } else {
                print_status_table(&registry);
            }
        }
        ModulesCmd::Preset(PresetCmd::Save { name }) => {
            let preset = Preset {
                name: name.clone(),
                states: registry.states_snapshot(),
            };
            presets.delete(&name); // replace any existing preset of the same name
            presets.save(preset.clone());
            save_presets(&preset_path, &presets.list())?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&preset)?);
            } else {
                println!(
                    "saved preset `{}` with {} module state(s) -> {}",
                    name,
                    preset.states.len(),
                    preset_path.display()
                );
            }
        }
        ModulesCmd::Preset(PresetCmd::Load { name }) => {
            let preset = presets
                .get(&name)
                .with_context(|| format!("no preset named `{name}`"))?;
            for (id, state) in &preset.states {
                registry.set_state(id, state.clone());
            }
            persist_states(&registry, &mut toml, &cfg_path)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&registry.list())?);
            } else {
                println!("loaded preset `{name}` ({} module state(s))", preset.states.len());
                print_module_table(&registry);
            }
        }
        ModulesCmd::Preset(PresetCmd::List) => {
            let all = presets.list();
            if args.json {
                println!("{}", serde_json::to_string_pretty(&all)?);
            } else if all.is_empty() {
                println!("no presets saved");
            } else {
                for p in &all {
                    println!("{}\t({} module state(s))", p.name, p.states.len());
                }
            }
        }
    }

    Ok(())
}

// ── persistence helpers ────────────────────────────────────────────────────────

/// Resolve the modules.toml path: explicit `--config`, else `~/.lancer/modules.toml`.
fn resolve_config_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("could not resolve home directory (set HOME/USERPROFILE or pass --config)")?;
    Ok(home.join(".lancer").join("modules.toml"))
}

/// Presets live next to the modules.toml as `presets.json`.
fn presets_path(cfg_path: &std::path::Path) -> PathBuf {
    cfg_path
        .parent()
        .map(|p| p.join("presets.json"))
        .unwrap_or_else(|| PathBuf::from("presets.json"))
}

/// Reflect persisted `ModulesToml` state into a fresh registry.
fn apply_toml_to_registry(registry: &ModuleRegistry, toml: &ModulesToml) {
    for (id, cfg) in &toml.modules {
        registry.set_state(id, state_from_config(cfg));
    }
}

/// Write the registry's current states back to `ModulesToml` on disk.
fn persist_states(registry: &ModuleRegistry, toml: &mut ModulesToml, path: &std::path::Path) -> Result<()> {
    let mut map: HashMap<String, ModuleConfig> = HashMap::new();
    for (id, state) in registry.states_snapshot() {
        map.insert(id, config_from_state(&state));
    }
    toml.modules = map;
    toml.save(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// `ModuleState` -> persisted `ModuleConfig`.
fn config_from_state(state: &ModuleState) -> ModuleConfig {
    match state {
        ModuleState::Off => ModuleConfig {
            state: "off".into(),
            auto_idle_timeout_min: None,
            sudo_method: None,
        },
        ModuleState::On => ModuleConfig {
            state: "on".into(),
            auto_idle_timeout_min: None,
            sudo_method: None,
        },
        ModuleState::Auto { idle_timeout_min } => ModuleConfig {
            state: "auto".into(),
            auto_idle_timeout_min: Some(*idle_timeout_min),
            sudo_method: None,
        },
    }
}

/// Persisted `ModuleConfig` -> `ModuleState`.
fn state_from_config(cfg: &ModuleConfig) -> ModuleState {
    match cfg.state.as_str() {
        "on" => ModuleState::On,
        "auto" => ModuleState::Auto {
            idle_timeout_min: cfg.auto_idle_timeout_min.unwrap_or(15),
        },
        _ => ModuleState::Off,
    }
}

fn load_presets(path: &std::path::Path) -> Result<Vec<Preset>> {
    match std::fs::read_to_string(path) {
        Ok(s) if !s.trim().is_empty() => Ok(serde_json::from_str(&s)
            .with_context(|| format!("failed to parse {}", path.display()))?),
        _ => Ok(Vec::new()),
    }
}

fn save_presets(path: &std::path::Path, presets: &[Preset]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let s = serde_json::to_string_pretty(presets)?;
    std::fs::write(path, s).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

// ── validation + display ─────────────────────────────────────────────────────

fn ensure_known(registry: &ModuleRegistry, id: &str) -> Result<()> {
    if registry.list().iter().any(|m| m.id == id) {
        Ok(())
    } else {
        let known: Vec<String> = registry.list().into_iter().map(|m| m.id).collect();
        anyhow::bail!("unknown module `{id}` (known: {})", known.join(", "))
    }
}

fn report_state(registry: &ModuleRegistry, id: &str, json: bool) -> Result<()> {
    let info = registry
        .list()
        .into_iter()
        .find(|m| m.id == id)
        .with_context(|| format!("module `{id}` vanished"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!("{}\t{}", info.id, state_label(&info.state));
    }
    Ok(())
}

fn print_module_table(registry: &ModuleRegistry) {
    let mut infos = registry.list();
    infos.sort_by(|a, b| a.id.cmp(&b.id));
    if infos.is_empty() {
        println!("no modules registered");
        return;
    }
    for m in &infos {
        let support = if m.platform_supported { "" } else { " [unsupported on this platform]" };
        let elev = if m.requires_elevation { " [needs elevation]" } else { "" };
        println!(
            "{:<14} {:<4} {:<14} {} ({} MB idle){}{}",
            m.id,
            state_label(&m.state),
            category_label(&m.category),
            m.name,
            m.estimated_idle_ram_kb / 1024,
            support,
            elev,
        );
    }
}

fn print_status_table(registry: &ModuleRegistry) {
    let mut infos = registry.list();
    infos.sort_by(|a, b| a.id.cmp(&b.id));
    if infos.is_empty() {
        println!("no modules registered");
        return;
    }
    for m in &infos {
        println!("{:<14} state={:<4} status={}", m.id, state_label(&m.state), status_label(&m.status));
    }
}

fn state_label(state: &ModuleState) -> &'static str {
    match state {
        ModuleState::Off => "off",
        ModuleState::On => "on",
        ModuleState::Auto { .. } => "auto",
    }
}

fn category_label(cat: &lancer_modules::ModuleCategory) -> &'static str {
    use lancer_modules::ModuleCategory::*;
    match cat {
        PluginRuntime => "plugin-runtime",
        NetworkService => "network-service",
        Background => "background",
        Platform => "platform",
    }
}

fn status_label(status: &lancer_modules::ModuleStatus) -> String {
    use lancer_modules::ModuleStatus::*;
    match status {
        Off => "off".to_string(),
        Starting => "starting".to_string(),
        Running { pid, ram_kb, since_unix } => {
            format!("running (pid={:?} ram_kb={ram_kb} since={since_unix})", pid)
        }
        Stopping => "stopping".to_string(),
        Failed { reason } => format!("failed: {reason}"),
    }
}
