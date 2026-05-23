//! Bambda-equivalent scripting host.
//!
//! Phase 1 ships just a minimal "compile + run with a request in scope"
//! function; Phase 5 expands this with filter contexts, custom-column
//! contexts, and a sandbox.

use anyhow::Result;
use lancer_core::{HttpRequest, HttpResponse};
use rhai::{Dynamic, Engine, Scope};

pub struct ScriptEngine {
    engine: Engine,
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
        Self { engine }
    }

    /// Evaluate a script with a single `req` variable in scope. The script must
    /// return a boolean — used for filtering.
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
}

fn request_to_dynamic(req: &HttpRequest) -> Dynamic {
    let mut map = rhai::Map::new();
    map.insert("method".into(), req.method.as_str().to_string().into());
    map.insert("path".into(), req.path.clone().into());
    map.insert("host".into(), req.meta.host.clone().into());
    map.insert("scheme".into(), req.meta.scheme.clone().into());
    map.insert("port".into(), (req.meta.port as i64).into());
    let mut headers = rhai::Map::new();
    for h in &req.headers {
        headers.insert(h.name.to_ascii_lowercase().into(), h.value.clone().into());
    }
    map.insert("headers".into(), headers.into());
    map.insert("body".into(), req.body_text().unwrap_or("").to_string().into());
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
    map.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_by_host() {
        let eng = ScriptEngine::new();
        let req = HttpRequest::builder("GET", "https://api.example.com/x").unwrap();
        let ok = eng.filter_request("req.host == \"api.example.com\"", &req).unwrap();
        assert!(ok);
    }
}
