//! Multi-language plugin host implementations.
//!
//! - `WasmHost` (feature `wasm`): wasmtime engine; plugins are .wasm files
//!   exporting `lancer_invoke(ptr: i32, len: i32) -> i64` where the input is
//!   a JSON-encoded `InvocationCtx` written into linear memory and the return
//!   packs `(ptr<<32)|len` of the JSON result, plus `lancer_alloc(len) -> i32`.
//! - `LuaHost` (feature `lua`): mlua with vendored Lua 5.4; plugins expose
//!   `function lancer_invoke(ctx) return result end`.
//! - `PythonHost` (feature `python`): pyo3; plugins are .py modules with
//!   `def lancer_invoke(ctx): return result`.
//!
//! Without the corresponding feature flag, each host returns a clear error.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostKind {
    Rhai,
    Wasm,
    Lua,
    Python,
    Native,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvocationCtx {
    pub event: String,
    pub request: Option<serde_json::Value>,
    pub response: Option<serde_json::Value>,
}

#[async_trait]
pub trait Host: Send + Sync {
    fn kind(&self) -> HostKind;
    async fn invoke(&self, plugin_id: &str, ctx: InvocationCtx) -> Result<serde_json::Value>;
}

// ============ WASM ============

#[cfg(feature = "wasm")]
pub struct WasmHost {
    engine: wasmtime::Engine,
    plugins: Mutex<std::collections::HashMap<String, Arc<wasmtime::Module>>>,
}

#[cfg(feature = "wasm")]
impl WasmHost {
    pub fn new() -> Self {
        Self { engine: wasmtime::Engine::default(), plugins: Mutex::new(Default::default()) }
    }
    pub fn load(&self, id: &str, path: &Path) -> Result<()> {
        let module = wasmtime::Module::from_file(&self.engine, path)?;
        self.plugins.lock().insert(id.to_string(), Arc::new(module));
        Ok(())
    }
}

#[cfg(feature = "wasm")]
#[async_trait]
impl Host for WasmHost {
    fn kind(&self) -> HostKind { HostKind::Wasm }
    async fn invoke(&self, plugin_id: &str, ctx: InvocationCtx) -> Result<serde_json::Value> {
        use wasmtime::{Linker, Store, Memory};
        let module = self
            .plugins
            .lock()
            .get(plugin_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown plugin {plugin_id}"))?;
        let mut store = Store::new(&self.engine, ());
        let linker = Linker::new(&self.engine);
        let instance = linker.instantiate(&mut store, &module)?;
        let memory: Memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow::anyhow!("plugin missing exported memory"))?;
        let alloc = instance.get_typed_func::<i32, i32>(&mut store, "lancer_alloc")?;
        let payload = serde_json::to_vec(&ctx)?;
        let ptr = alloc.call(&mut store, payload.len() as i32)?;
        memory.write(&mut store, ptr as usize, &payload)?;
        let invoke = instance.get_typed_func::<(i32, i32), i64>(&mut store, "lancer_invoke")?;
        let packed = invoke.call(&mut store, (ptr, payload.len() as i32))?;
        let out_ptr = (packed >> 32) as i32;
        let out_len = (packed & 0xFFFF_FFFF) as i32;
        let mut buf = vec![0u8; out_len as usize];
        memory.read(&store, out_ptr as usize, &mut buf)?;
        Ok(serde_json::from_slice(&buf)?)
    }
}

#[cfg(not(feature = "wasm"))]
pub struct WasmHost;

#[cfg(not(feature = "wasm"))]
#[async_trait]
impl Host for WasmHost {
    fn kind(&self) -> HostKind { HostKind::Wasm }
    async fn invoke(&self, _id: &str, _ctx: InvocationCtx) -> Result<serde_json::Value> {
        anyhow::bail!("WASM host disabled — rebuild with `--features wasm`")
    }
}

// ============ Lua ============

#[cfg(feature = "lua")]
pub struct LuaHost {
    plugins: Mutex<std::collections::HashMap<String, String>>,
}

#[cfg(feature = "lua")]
impl LuaHost {
    pub fn new() -> Self { Self { plugins: Mutex::new(Default::default()) } }
    pub fn load(&self, id: &str, body: &str) {
        self.plugins.lock().insert(id.to_string(), body.to_string());
    }
    pub fn load_file(&self, id: &str, path: &Path) -> Result<()> {
        let body = std::fs::read_to_string(path)?;
        self.load(id, &body);
        Ok(())
    }
}

#[cfg(feature = "lua")]
fn json_to_lua<'lua>(lua: &'lua mlua::Lua, v: &serde_json::Value) -> mlua::Result<mlua::Value<'lua>> {
    use mlua::Value;
    Ok(match v {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() { Value::Integer(i) }
            else if let Some(f) = n.as_f64() { Value::Number(f) }
            else { Value::Nil }
        }
        serde_json::Value::String(s) => Value::String(lua.create_string(s)?),
        serde_json::Value::Array(arr) => {
            let t = lua.create_table()?;
            for (i, x) in arr.iter().enumerate() {
                t.set(i + 1, json_to_lua(lua, x)?)?;
            }
            Value::Table(t)
        }
        serde_json::Value::Object(map) => {
            let t = lua.create_table()?;
            for (k, x) in map {
                t.set(k.as_str(), json_to_lua(lua, x)?)?;
            }
            Value::Table(t)
        }
    })
}

#[cfg(feature = "lua")]
fn lua_to_json(v: mlua::Value<'_>) -> mlua::Result<serde_json::Value> {
    use mlua::Value;
    Ok(match v {
        Value::Nil => serde_json::Value::Null,
        Value::Boolean(b) => serde_json::Value::Bool(b),
        Value::Integer(i) => serde_json::Value::Number(serde_json::Number::from(i)),
        Value::Number(f) => serde_json::Number::from_f64(f).map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null),
        Value::String(s) => serde_json::Value::String(s.to_str()?.to_string()),
        Value::Table(t) => {
            let len = t.raw_len();
            if len > 0 {
                let mut arr = Vec::with_capacity(len);
                for i in 1..=len { arr.push(lua_to_json(t.raw_get(i)?)?); }
                serde_json::Value::Array(arr)
            } else {
                let mut obj = serde_json::Map::new();
                for pair in t.pairs::<String, Value>() {
                    let (k, v) = pair?;
                    obj.insert(k, lua_to_json(v)?);
                }
                serde_json::Value::Object(obj)
            }
        }
        _ => serde_json::Value::Null,
    })
}

#[cfg(feature = "lua")]
#[async_trait]
impl Host for LuaHost {
    fn kind(&self) -> HostKind { HostKind::Lua }
    async fn invoke(&self, plugin_id: &str, ctx: InvocationCtx) -> Result<serde_json::Value> {
        let body = self
            .plugins
            .lock()
            .get(plugin_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown plugin {plugin_id}"))?;
        let lua = mlua::Lua::new();
        lua.load(&body).exec()?;
        let invoke: mlua::Function = lua.globals().get("lancer_invoke")?;
        let arg = json_to_lua(&lua, &serde_json::to_value(&ctx)?)?;
        let ret: mlua::Value = invoke.call(arg)?;
        Ok(lua_to_json(ret)?)
    }
}

#[cfg(not(feature = "lua"))]
pub struct LuaHost;

#[cfg(not(feature = "lua"))]
#[async_trait]
impl Host for LuaHost {
    fn kind(&self) -> HostKind { HostKind::Lua }
    async fn invoke(&self, _id: &str, _ctx: InvocationCtx) -> Result<serde_json::Value> {
        anyhow::bail!("Lua host disabled — rebuild with `--features lua`")
    }
}

// ============ Python ============

#[cfg(feature = "python")]
pub struct PythonHost {
    plugins: Mutex<std::collections::HashMap<String, PathBuf>>,
}

#[cfg(feature = "python")]
impl PythonHost {
    pub fn new() -> Self { Self { plugins: Mutex::new(Default::default()) } }
    pub fn load(&self, id: &str, path: &Path) {
        self.plugins.lock().insert(id.to_string(), path.to_path_buf());
    }
}

#[cfg(feature = "python")]
#[async_trait]
impl Host for PythonHost {
    fn kind(&self) -> HostKind { HostKind::Python }
    async fn invoke(&self, plugin_id: &str, ctx: InvocationCtx) -> Result<serde_json::Value> {
        use pyo3::prelude::*;
        use pyo3::types::PyDict;
        let path = self
            .plugins
            .lock()
            .get(plugin_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown plugin {plugin_id}"))?;
        let body = std::fs::read_to_string(&path)?;
        let ctx_json = serde_json::to_string(&ctx)?;
        let result = Python::with_gil(|py| -> PyResult<String> {
            let globals = PyDict::new_bound(py);
            py.run_bound(&body, Some(&globals), None)?;
            let invoke = globals
                .get_item("lancer_invoke")?
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyAttributeError, _>("lancer_invoke missing"))?;
            let json_mod = py.import_bound("json")?;
            let parsed = json_mod.call_method1("loads", (ctx_json.as_str(),))?;
            let res = invoke.call1((parsed,))?;
            let dumped = json_mod.call_method1("dumps", (res,))?;
            dumped.extract::<String>()
        }).map_err(|e| anyhow::anyhow!("python error: {e}"))?;
        Ok(serde_json::from_str(&result)?)
    }
}

#[cfg(not(feature = "python"))]
pub struct PythonHost;

#[cfg(not(feature = "python"))]
#[async_trait]
impl Host for PythonHost {
    fn kind(&self) -> HostKind { HostKind::Python }
    async fn invoke(&self, _id: &str, _ctx: InvocationCtx) -> Result<serde_json::Value> {
        anyhow::bail!("Python host disabled — rebuild with `--features python`")
    }
}
