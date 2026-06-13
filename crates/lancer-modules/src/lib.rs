//! §52 Modules System — opt-in module registry.
//!
//! Modular runtime architecture so Lancer starts at ~80 MB with all heavy
//! features dormant. User opts in per module from the Settings → Modules page.
//! First-run defaults: everything OFF.

use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ModuleCategory {
    PluginRuntime,
    NetworkService,
    Background,
    Platform,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModuleState {
    Off,
    On,
    Auto { idle_timeout_min: u32 },
}

impl Default for ModuleState {
    fn default() -> Self { ModuleState::Off }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ModuleStatus {
    Off,
    Starting,
    Running {
        pid: Option<u32>,
        ram_kb: u64,
        since_unix: i64,
    },
    Stopping,
    Failed { reason: String },
}

impl Default for ModuleStatus {
    fn default() -> Self { ModuleStatus::Off }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: ModuleCategory,
    pub estimated_idle_ram_kb: u64,
    pub platform_supported: bool,
    pub requires_elevation: bool,
    pub state: ModuleState,
    pub status: ModuleStatus,
}

// ── Module trait ──────────────────────────────────────────────────────────────

#[async_trait]
pub trait LancerModule: Send + Sync + 'static {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn category(&self) -> ModuleCategory;
    fn estimated_idle_ram_kb(&self) -> u64;
    fn platform_supported(&self) -> bool { true }
    fn requires_elevation(&self) -> bool { false }
    async fn start(&self) -> anyhow::Result<ModuleHandle>;
    async fn stop(&self, handle: ModuleHandle) -> anyhow::Result<()>;
}

pub struct ModuleHandle {
    pub started_at: Instant,
    /// in-process modules carry a JoinHandle + cancel sender
    pub join: Option<JoinHandle<()>>,
    pub cancel: Option<oneshot::Sender<()>>,
    /// subprocess modules carry a pid we can signal
    pub pid: Option<u32>,
}

// ── Registry ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ModuleRegistry {
    modules: Arc<RwLock<HashMap<&'static str, Arc<dyn LancerModule>>>>,
    handles: Arc<RwLock<HashMap<&'static str, ModuleHandle>>>,
    states: Arc<RwLock<HashMap<String, ModuleState>>>,
    statuses: Arc<RwLock<HashMap<&'static str, ModuleStatus>>>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self {
            modules: Arc::new(RwLock::new(HashMap::new())),
            handles: Arc::new(RwLock::new(HashMap::new())),
            states: Arc::new(RwLock::new(HashMap::new())),
            statuses: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn register<M: LancerModule + 'static>(&self, m: M) {
        let id = m.id();
        self.modules.write().insert(id, Arc::new(m));
        self.statuses.write().insert(id, ModuleStatus::Off);
        self.states.write().entry(id.to_string()).or_insert(ModuleState::Off);
    }

    pub fn register_boxed(&self, m: Box<dyn LancerModule>) {
        let id = m.id();
        let arc: Arc<dyn LancerModule> = Arc::from(m);
        self.modules.write().insert(id, arc);
        self.statuses.write().insert(id, ModuleStatus::Off);
        self.states.write().entry(id.to_string()).or_insert(ModuleState::Off);
    }

    pub fn list(&self) -> Vec<ModuleInfo> {
        let modules = self.modules.read();
        let states = self.states.read();
        let statuses = self.statuses.read();
        modules.values().map(|m| {
            ModuleInfo {
                id: m.id().into(),
                name: m.name().into(),
                description: m.description().into(),
                category: m.category(),
                estimated_idle_ram_kb: m.estimated_idle_ram_kb(),
                platform_supported: m.platform_supported(),
                requires_elevation: m.requires_elevation(),
                state: states.get(m.id()).cloned().unwrap_or_default(),
                status: statuses.get(m.id()).cloned().unwrap_or_default(),
            }
        }).collect()
    }

    pub async fn start(&self, id: &str) -> anyhow::Result<()> {
        let m = self.modules.read().get(id).cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown module: {id}"))?;
        if self.handles.read().contains_key(m.id()) { return Ok(()); }
        if !m.platform_supported() {
            anyhow::bail!("module `{id}` is not supported on this platform");
        }
        self.statuses.write().insert(m.id(), ModuleStatus::Starting);
        let handle = match m.start().await {
            Ok(h) => h,
            Err(e) => {
                self.statuses.write().insert(m.id(), ModuleStatus::Failed { reason: e.to_string() });
                return Err(e);
            }
        };
        let pid = handle.pid;
        let since_unix = chrono::Utc::now().timestamp();
        self.handles.write().insert(m.id(), handle);
        self.statuses.write().insert(m.id(), ModuleStatus::Running {
            pid,
            ram_kb: m.estimated_idle_ram_kb(),
            since_unix,
        });
        self.states.write().insert(m.id().to_string(), ModuleState::On);
        Ok(())
    }

    pub async fn stop(&self, id: &str) -> anyhow::Result<()> {
        let m = self.modules.read().get(id).cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown module: {id}"))?;
        let handle = self.handles.write().remove(m.id());
        let Some(handle) = handle else {
            self.states.write().insert(m.id().to_string(), ModuleState::Off);
            self.statuses.write().insert(m.id(), ModuleStatus::Off);
            return Ok(());
        };
        self.statuses.write().insert(m.id(), ModuleStatus::Stopping);
        m.stop(handle).await?;
        self.statuses.write().insert(m.id(), ModuleStatus::Off);
        self.states.write().insert(m.id().to_string(), ModuleState::Off);
        Ok(())
    }

    pub fn set_state(&self, id: &str, state: ModuleState) {
        self.states.write().insert(id.to_string(), state);
    }

    pub fn states_snapshot(&self) -> HashMap<String, ModuleState> {
        self.states.read().clone()
    }
}

impl Default for ModuleRegistry {
    fn default() -> Self { Self::new() }
}

// ── Built-in modules ──────────────────────────────────────────────────────────

/// In-process task module — cheapest flavor. Spawns a tokio task; cancels on stop.
pub struct InProcessModule {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub category: ModuleCategory,
    pub estimated_idle_ram_kb: u64,
}

#[async_trait]
impl LancerModule for InProcessModule {
    fn id(&self) -> &'static str { self.id }
    fn name(&self) -> &'static str { self.name }
    fn description(&self) -> &'static str { self.description }
    fn category(&self) -> ModuleCategory { self.category }
    fn estimated_idle_ram_kb(&self) -> u64 { self.estimated_idle_ram_kb }
    async fn start(&self) -> anyhow::Result<ModuleHandle> {
        let (tx, rx) = oneshot::channel();
        let id = self.id;
        let join = tokio::spawn(async move {
            // Idle loop — module would tick whatever its real work is.
            let _ = id;
            tokio::select! {
                _ = rx => {}
                _ = futures_pending() => {}
            }
        });
        Ok(ModuleHandle {
            started_at: Instant::now(),
            join: Some(join),
            cancel: Some(tx),
            pid: None,
        })
    }
    async fn stop(&self, mut handle: ModuleHandle) -> anyhow::Result<()> {
        if let Some(c) = handle.cancel.take() {
            let _ = c.send(());
        }
        if let Some(j) = handle.join.take() {
            let _ = j.await;
        }
        Ok(())
    }
}

async fn futures_pending() {
    std::future::pending::<()>().await;
}

/// The 7-module default batch.
pub fn default_modules() -> Vec<Box<dyn LancerModule>> {
    use ModuleCategory::*;
    vec![
        Box::new(InProcessModule {
            id: "jvm",
            name: "JVM plugin host",
            description: "Run Burp Montoya-compatible Java/Kotlin plugins (subprocess).",
            category: PluginRuntime,
            estimated_idle_ram_kb: 80 * 1024,
        }),
        Box::new(InProcessModule {
            id: "python",
            name: "Python plugin host",
            description: "Run Python plugins (subprocess).",
            category: PluginRuntime,
            estimated_idle_ram_kb: 15 * 1024,
        }),
        Box::new(InProcessModule {
            id: "wasm",
            name: "WASM plugin host",
            description: "Run WASM plugins (subprocess).",
            category: PluginRuntime,
            estimated_idle_ram_kb: 8 * 1024,
        }),
        Box::new(InProcessModule {
            id: "collab",
            name: "Live multi-tester sync",
            description: "Real-time peer presence and project sync.",
            category: NetworkService,
            estimated_idle_ram_kb: 3 * 1024,
        }),
        Box::new(InProcessModule {
            id: "oast-server",
            name: "Self-hosted Collaborator",
            description: "Wildcard DNS / HTTP / SMTP OAST server.",
            category: NetworkService,
            estimated_idle_ram_kb: 5 * 1024,
        }),
        Box::new(InProcessModule {
            id: "scheduler",
            name: "Cron / scheduled scans",
            description: "Background scheduler for periodic tasks.",
            category: Background,
            estimated_idle_ram_kb: 1 * 1024,
        }),
        Box::new(EbpfModule {
            id: "ebpf",
            name: "Kernel-level traffic capture",
            description: "Linux only — requires root. Captures via eBPF.",
            category: Platform,
            estimated_idle_ram_kb: 12 * 1024,
        }),
    ]
}

/// Privileged daemon — eBPF. Requires root on Linux; reported unsupported elsewhere.
pub struct EbpfModule {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub category: ModuleCategory,
    pub estimated_idle_ram_kb: u64,
}

#[async_trait]
impl LancerModule for EbpfModule {
    fn id(&self) -> &'static str { self.id }
    fn name(&self) -> &'static str { self.name }
    fn description(&self) -> &'static str { self.description }
    fn category(&self) -> ModuleCategory { self.category }
    fn estimated_idle_ram_kb(&self) -> u64 { self.estimated_idle_ram_kb }
    fn platform_supported(&self) -> bool { cfg!(target_os = "linux") }
    fn requires_elevation(&self) -> bool { true }
    async fn start(&self) -> anyhow::Result<ModuleHandle> {
        if !cfg!(target_os = "linux") {
            anyhow::bail!("eBPF capture is Linux-only");
        }
        // Spawn the privileged probe next to this binary (pkexec → sudo fallback).
        // The probe loads the BPF programs and streams captured flows.
        let probe = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("lancer-ebpf-probe")))
            .unwrap_or_else(|| std::path::PathBuf::from("lancer-ebpf-probe"));
        let child = std::process::Command::new("pkexec")
            .arg(&probe)
            .spawn()
            .or_else(|_| std::process::Command::new("sudo").arg(&probe).spawn())
            .map_err(|e| {
                anyhow::anyhow!("failed to spawn eBPF probe (needs pkexec/sudo + lancer-ebpf-probe present): {e}")
            })?;
        let pid = child.id();
        // std::process::Child detaches (does not kill) on drop; we track the pid.
        Ok(ModuleHandle {
            started_at: Instant::now(),
            join: None,
            cancel: None,
            pid: Some(pid),
        })
    }
    async fn stop(&self, handle: ModuleHandle) -> anyhow::Result<()> {
        if let Some(pid) = handle.pid {
            let _ = std::process::Command::new("pkexec")
                .args(["kill", "-TERM", &pid.to_string()])
                .status()
                .or_else(|_| {
                    std::process::Command::new("kill")
                        .args(["-TERM", &pid.to_string()])
                        .status()
                });
        }
        Ok(())
    }
}

// ── modules.toml persistence ──────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ModulesToml {
    #[serde(default)]
    pub modules: HashMap<String, ModuleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub auto_idle_timeout_min: Option<u32>,
    #[serde(default)]
    pub sudo_method: Option<String>,
}

impl ModulesToml {
    pub fn load(path: &std::path::Path) -> Self {
        std::fs::read_to_string(path).ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }
    pub fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let s = toml::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(path, s)?;
        Ok(())
    }
}

// ── Snapshots (presets) ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preset {
    pub name: String,
    pub states: HashMap<String, ModuleState>,
}

#[derive(Debug, Default, Clone)]
pub struct PresetStore {
    inner: Arc<RwLock<Vec<Preset>>>,
}

impl PresetStore {
    pub fn new() -> Self { Self::default() }
    pub fn save(&self, p: Preset) { self.inner.write().push(p); }
    pub fn list(&self) -> Vec<Preset> { self.inner.read().clone() }
    pub fn get(&self, name: &str) -> Option<Preset> {
        self.inner.read().iter().find(|p| p.name == name).cloned()
    }
    pub fn delete(&self, name: &str) {
        self.inner.write().retain(|p| p.name != name);
    }
}
