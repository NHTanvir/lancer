//! Bambda-equivalent scripting host (Rhai-based).
//!
//! Scripts run with a typed map representing the request/response in scope.
//! Used for:
//! - Filtering HTTP history, WebSocket history, Logger, Site map
//! - Custom columns
//! - Custom actions in Repeater
//! - Custom passive scan checks
//! - Match-and-replace
//!
//! The runtime is sandboxed: scripts cannot perform I/O. They receive readonly
//! request/response data and must return a typed value (bool for filters,
//! string for custom columns, map for custom actions).

use std::sync::Arc;

use anyhow::Result;
use lancer_core::{HttpRequest, HttpResponse};
use parking_lot::RwLock;
use rhai::{Dynamic, Engine, Scope};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct ScriptEngine {
    engine: Arc<Engine>,
    library: Arc<RwLock<Library>>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Library {
    pub items: Vec<LibraryItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryItem {
    pub id: String,
    pub name: String,
    pub kind: ScriptKind,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptKind {
    FilterRequest,
    FilterResponse,
    CustomColumn,
    CustomAction,
    PassiveCheck,
    MatchReplace,
}

impl Default for ScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptEngine {
    pub fn new() -> Self {
        let mut engine = Engine::new();
        engine.set_max_expr_depths(64, 32);
        engine.set_max_operations(1_000_000);
        engine.set_max_string_size(1024 * 1024);
        engine.set_max_array_size(50_000);
        engine.set_max_map_size(50_000);
        Self {
            engine: Arc::new(engine),
            library: Arc::new(RwLock::new(Library::default())),
        }
    }

    pub fn library(&self) -> Library {
        self.library.read().clone()
    }

    pub fn install(&self, item: LibraryItem) {
        let mut lib = self.library.write();
        lib.items.retain(|i| i.id != item.id);
        lib.items.push(item);
    }

    pub fn remove(&self, id: &str) {
        self.library.write().items.retain(|i| i.id != id);
    }

    /// Evaluate a request filter. Script must return a boolean.
    pub fn filter_request(&self, script: &str, req: &HttpRequest) -> Result<bool> {
        let mut scope = Scope::new();
        scope.push_dynamic("req", request_to_dynamic(req));
        let v: Dynamic = self.engine.eval_with_scope(&mut scope, script)?;
        Ok(v.as_bool().unwrap_or(false))
    }

    pub fn filter_response(&self, script: &str, resp: &HttpResponse) -> Result<bool> {
        let mut scope = Scope::new();
        scope.push_dynamic("resp", response_to_dynamic(resp));
        let v: Dynamic = self.engine.eval_with_scope(&mut scope, script)?;
        Ok(v.as_bool().unwrap_or(false))
    }

    /// Custom-column script: must return a string (the cell value).
    pub fn custom_column(
        &self,
        script: &str,
        req: &HttpRequest,
        resp: Option<&HttpResponse>,
    ) -> Result<String> {
        let mut scope = Scope::new();
        scope.push_dynamic("req", request_to_dynamic(req));
        if let Some(r) = resp {
            scope.push_dynamic("resp", response_to_dynamic(r));
        }
        let v: Dynamic = self.engine.eval_with_scope(&mut scope, script)?;
        Ok(v.into_string().unwrap_or_default())
    }

    /// Custom action: script returns a map describing an action
    /// (`type`/`value` etc.). The host interprets the result.
    pub fn custom_action(
        &self,
        script: &str,
        req: &HttpRequest,
    ) -> Result<serde_json::Value> {
        let mut scope = Scope::new();
        scope.push_dynamic("req", request_to_dynamic(req));
        let v: Dynamic = self.engine.eval_with_scope(&mut scope, script)?;
        Ok(dynamic_to_json(v))
    }

    /// Passive-check script: returns a list of issue maps.
    pub fn passive_check(
        &self,
        script: &str,
        req: &HttpRequest,
        resp: &HttpResponse,
    ) -> Result<Vec<serde_json::Value>> {
        let mut scope = Scope::new();
        scope.push_dynamic("req", request_to_dynamic(req));
        scope.push_dynamic("resp", response_to_dynamic(resp));
        let v: Dynamic = self.engine.eval_with_scope(&mut scope, script)?;
        let json = dynamic_to_json(v);
        Ok(match json {
            serde_json::Value::Array(a) => a,
            _ => Vec::new(),
        })
    }
}

fn request_to_dynamic(req: &HttpRequest) -> Dynamic {
    let mut map = rhai::Map::new();
    map.insert("method".into(), req.method.as_str().to_string().into());
    map.insert("path".into(), req.path.clone().into());
    map.insert("url".into(), req.url().into());
    map.insert("host".into(), req.meta.host.clone().into());
    map.insert("scheme".into(), req.meta.scheme.clone().into());
    map.insert("port".into(), (req.meta.port as i64).into());
    let mut headers = rhai::Map::new();
    for h in &req.headers {
        headers.insert(h.name.to_ascii_lowercase().into(), h.value.clone().into());
    }
    map.insert("headers".into(), headers.into());
    map.insert("body".into(), req.body_text().unwrap_or("").to_string().into());
    map.insert("body_len".into(), (req.body.len() as i64).into());
    map.into()
}

fn response_to_dynamic(resp: &HttpResponse) -> Dynamic {
    let mut map = rhai::Map::new();
    map.insert("status".into(), (resp.status as i64).into());
    map.insert("reason".into(), resp.reason.clone().into());
    let mut headers = rhai::Map::new();
    for h in &resp.headers {
        headers.insert(h.name.to_ascii_lowercase().into(), h.value.clone().into());
    }
    map.insert("headers".into(), headers.into());
    map.insert("body".into(), resp.body_text().unwrap_or("").to_string().into());
    map.insert("body_len".into(), (resp.body.len() as i64).into());
    map.insert("elapsed_ms".into(), (resp.elapsed_ms.unwrap_or(0) as i64).into());
    map.into()
}

fn dynamic_to_json(v: Dynamic) -> serde_json::Value {
    use serde_json::Value as J;
    if v.is::<bool>() {
        J::Bool(v.as_bool().unwrap())
    } else if v.is::<i64>() {
        J::Number(serde_json::Number::from(v.as_int().unwrap()))
    } else if v.is::<f64>() {
        serde_json::Number::from_f64(v.as_float().unwrap())
            .map(J::Number)
            .unwrap_or(J::Null)
    } else if v.is::<String>() {
        J::String(v.into_string().unwrap_or_default())
    } else if v.is::<rhai::Array>() {
        let arr = v.cast::<rhai::Array>();
        J::Array(arr.into_iter().map(dynamic_to_json).collect())
    } else if v.is::<rhai::Map>() {
        let m = v.cast::<rhai::Map>();
        let mut obj = serde_json::Map::new();
        for (k, vv) in m {
            obj.insert(k.to_string(), dynamic_to_json(vv));
        }
        J::Object(obj)
    } else if v.is_unit() {
        J::Null
    } else {
        J::String(v.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_by_host() {
        let eng = ScriptEngine::new();
        let req = HttpRequest::builder("GET", "https://api.example.com/x").unwrap();
        assert!(eng.filter_request("req.host == \"api.example.com\"", &req).unwrap());
        assert!(!eng.filter_request("req.host == \"other.com\"", &req).unwrap());
    }

    #[test]
    fn custom_column_returns_string() {
        let eng = ScriptEngine::new();
        let req = HttpRequest::builder("GET", "https://x.com/").unwrap();
        let s = eng
            .custom_column("req.method + \" \" + req.host", &req, None)
            .unwrap();
        assert_eq!(s, "GET x.com");
    }
}
