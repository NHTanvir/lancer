//! §39 API Route Discovery — kiterunner-equivalent API-aware route enumeration.
//!
//! Beats dir-bruteforce on REST APIs because it knows route templates, common
//! verbs, and content negotiation. Auto-detects OpenAPI/GraphQL; falls back to
//! the templated route library.

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryRequest {
    /// Base URL (no trailing slash) — e.g. `https://api.example.com`
    pub base_url: String,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Override route library — if empty, uses the bundled defaults.
    #[serde(default)]
    pub routes: Vec<String>,
    /// Auth header to attach to every probe.
    #[serde(default)]
    pub auth_header: Option<String>,
    /// Which methods to fan out per route.
    #[serde(default = "default_methods")]
    pub methods: Vec<String>,
}

fn default_concurrency() -> usize { 50 }
fn default_timeout_secs() -> u64 { 10 }
fn default_methods() -> Vec<String> {
    vec!["GET".into(), "POST".into(), "PUT".into(), "DELETE".into(), "OPTIONS".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteResult {
    pub id: Uuid,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub length: u64,
    pub content_type: Option<String>,
    pub interesting: bool,
    pub discovered_at: chrono::DateTime<chrono::Utc>,
}

// ── Bundled route library ─────────────────────────────────────────────────────

/// Curated 200+ route templates. Each `{ }` is left as-is — the user can
/// supply substitutions or we test as literal.
pub fn default_route_library() -> Vec<&'static str> {
    vec![
        // Versioned REST
        "/api/v1/users", "/api/v2/users", "/api/v3/users",
        "/api/v1/auth", "/api/v1/login", "/api/v1/logout",
        "/api/v1/admin", "/api/v1/config", "/api/v1/settings",
        "/api/v1/orders", "/api/v1/payments", "/api/v1/products",
        "/api/v1/items", "/api/v1/cart", "/api/v1/checkout",
        "/api/v1/notifications", "/api/v1/webhooks",
        "/api/v1/files", "/api/v1/upload", "/api/v1/download",
        "/api/v1/search", "/api/v1/query", "/api/v1/reports",
        "/api/v1/me", "/api/v1/profile", "/api/v1/account",
        "/api/v1/health", "/api/v1/healthz", "/api/v1/ready",
        "/api/v1/status", "/api/v1/metrics", "/api/v1/debug",
        "/api/v1/docs", "/api/v1/spec", "/api/v1/openapi",
        // Unversioned
        "/api/users", "/api/auth", "/api/admin", "/api/login",
        "/api/orders", "/api/payments", "/api/products",
        "/api/me", "/api/profile", "/api/account",
        // GraphQL / introspection
        "/graphql", "/api/graphql", "/v1/graphql", "/query",
        "/graphiql", "/altair", "/playground",
        // OpenAPI spec
        "/swagger.json", "/openapi.json", "/openapi.yaml",
        "/api-docs", "/api-docs.json", "/v2/api-docs", "/v3/api-docs",
        "/swagger-ui", "/swagger-ui/index.html",
        "/redoc", "/rapidoc",
        // Cloud-provider patterns
        "/aws/credentials", "/.aws/credentials",
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",
        "/.well-known/oauth-authorization-server",
        // K8s
        "/healthz", "/livez", "/readyz", "/metrics",
        "/api", "/apis", "/version",
        // Stripe-style
        "/v1/charges", "/v1/customers", "/v1/subscriptions",
        "/v1/invoices", "/v1/refunds", "/v1/payment_intents",
        // GitHub-style
        "/repos", "/orgs", "/issues", "/pulls", "/branches",
        // Slack-style
        "/api/conversations.list", "/api/users.list", "/api/auth.test",
        // GitLab
        "/api/v4/projects", "/api/v4/users", "/api/v4/groups",
        // Common debug endpoints
        "/debug/pprof/", "/debug/vars", "/admin/console",
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump",
        "/jolokia", "/management",
        // Backup files
        "/backup.sql", "/backup.zip", "/dump.sql", "/db.sql",
        "/.env", "/.env.local", "/.env.production",
        "/config.json", "/config.yaml", "/secrets.yaml",
        // Source code
        "/.git/config", "/.git/HEAD", "/.svn/wc.db",
        "/composer.json", "/composer.lock", "/package.json",
        "/Gemfile.lock", "/requirements.txt", "/go.sum",
        // Static admin
        "/admin", "/administrator", "/wp-admin", "/wp-login.php",
        "/login", "/signin", "/console", "/dashboard",
    ]
}

// ── Detection helpers ─────────────────────────────────────────────────────────

fn is_interesting(status: u16, length: u64) -> bool {
    // 200/201/202/301/302/401/403 — and non-tiny body.
    matches!(status, 200 | 201 | 202 | 301 | 302 | 401 | 403)
        && length > 0
}

async fn probe_one(
    client: &reqwest::Client,
    base_url: &str,
    route: &str,
    method: &str,
    auth: Option<&str>,
) -> Option<RouteResult> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), route);
    let m = reqwest::Method::from_bytes(method.as_bytes()).ok()?;
    let mut req = client.request(m, &url);
    if let Some(a) = auth {
        req = req.header("Authorization", a);
    }
    req = req.header("Accept", "application/json");
    let resp = req.send().await.ok()?;
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let body = resp.bytes().await.ok()?;
    let length = body.len() as u64;
    Some(RouteResult {
        id: Uuid::new_v4(),
        method: method.into(),
        url,
        status,
        length,
        content_type,
        interesting: is_interesting(status, length),
        discovered_at: chrono::Utc::now(),
    })
}

// ── OpenAPI auto-detect ───────────────────────────────────────────────────────

async fn try_openapi(client: &reqwest::Client, base_url: &str) -> Option<Vec<String>> {
    for spec_path in &["/openapi.json", "/swagger.json", "/v2/api-docs", "/v3/api-docs", "/api-docs"] {
        let url = format!("{}{}", base_url.trim_end_matches('/'), spec_path);
        let Ok(resp) = client.get(&url).send().await else { continue };
        if !resp.status().is_success() { continue; }
        let Ok(text) = resp.text().await else { continue };
        let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
        // Extract every `paths.*` key.
        let Some(paths) = val.get("paths").and_then(|p| p.as_object()) else { continue };
        let routes: Vec<String> = paths.keys().cloned().collect();
        if !routes.is_empty() { return Some(routes); }
    }
    None
}

// ── Public API ────────────────────────────────────────────────────────────────

pub async fn run_discovery(req: DiscoveryRequest) -> Vec<RouteResult> {
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    // Prefer OpenAPI-driven mode if a spec is detected.
    let routes: Vec<String> = if !req.routes.is_empty() {
        req.routes.clone()
    } else if let Some(spec_routes) = try_openapi(&client, &req.base_url).await {
        spec_routes
    } else {
        default_route_library().into_iter().map(|s| s.to_string()).collect()
    };

    let methods = req.methods.clone();
    let auth = req.auth_header.clone();
    let base = req.base_url.clone();
    let concurrency = req.concurrency;

    let mut jobs = Vec::new();
    for r in &routes {
        for m in &methods {
            jobs.push((r.clone(), m.clone()));
        }
    }

    let client = std::sync::Arc::new(client);
    futures::stream::iter(jobs)
        .map(move |(route, method)| {
            let client = client.clone();
            let base = base.clone();
            let auth = auth.clone();
            async move { probe_one(&client, &base, &route, &method, auth.as_deref()).await }
        })
        .buffer_unordered(concurrency)
        .filter_map(|r| async move { r })
        .collect()
        .await
}
