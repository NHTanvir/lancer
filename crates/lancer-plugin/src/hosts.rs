//! Multi-language plugin host interfaces.
//!
//! Each host is feature-gated so the dependencies stay opt-in:
//!   `--features wasm`   pulls in wasmtime
//!   `--features lua`    pulls in mlua
//!   `--features python` pulls in pyo3
//!
//! Without any feature flag, only the in-process Rust path + Rhai (via
//! `lancer_script`) is available; the loader traits below still compile so
//! callers can wire them up.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostKind {
    Rhai,
    Wasm,
    Lua,
    Python,
    Native,
}

/// A "plugin invocation context" the host passes to a plugin entrypoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvocationCtx {
    pub event: String,
    pub request: Option<serde_json::Value>,
    pub response: Option<serde_json::Value>,
}

/// A plugin host knows how to load a plugin once and invoke it many times.
#[async_trait]
pub trait Host: Send + Sync {
    fn kind(&self) -> HostKind;
    async fn invoke(&self, plugin_id: &str, ctx: InvocationCtx) -> Result<serde_json::Value>;
}

/// Stub WASM host. Replace the body with `wasmtime::Engine`/`Instance` once
/// the `wasm` feature is added.
pub struct WasmHost;

#[async_trait]
impl Host for WasmHost {
    fn kind(&self) -> HostKind {
        HostKind::Wasm
    }
    async fn invoke(&self, _id: &str, _ctx: InvocationCtx) -> Result<serde_json::Value> {
        anyhow::bail!("WASM host disabled — rebuild with `--features wasm`")
    }
}

pub struct LuaHost;

#[async_trait]
impl Host for LuaHost {
    fn kind(&self) -> HostKind {
        HostKind::Lua
    }
    async fn invoke(&self, _id: &str, _ctx: InvocationCtx) -> Result<serde_json::Value> {
        anyhow::bail!("Lua host disabled — rebuild with `--features lua`")
    }
}

pub struct PythonHost;

#[async_trait]
impl Host for PythonHost {
    fn kind(&self) -> HostKind {
        HostKind::Python
    }
    async fn invoke(&self, _id: &str, _ctx: InvocationCtx) -> Result<serde_json::Value> {
        anyhow::bail!("Python host disabled — rebuild with `--features python`")
    }
}
