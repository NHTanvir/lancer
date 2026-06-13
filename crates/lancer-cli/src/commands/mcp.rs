//! `lancer mcp` — §58 expose Lancer to AI agents over the Model Context Protocol.
//!
//! A JSON-RPC 2.0 **stdio** MCP server (newline-delimited). It advertises a set
//! of tools that proxy to a running `lancer-api` instance, so an AI client
//! (Claude Desktop / Claude Code / any MCP host) can drive the whole workbench:
//! send Repeater requests, run scans, generate Collaborator payloads, fuzz, etc.
//!
//! Usage: `lancer mcp --api http://127.0.0.1:9191`, then point your MCP client
//! at this command as a stdio server.

use anyhow::Result;
use clap::Args;
use lancer_core::HttpRequest;
use lancer_tools::HttpClient;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Debug, Args)]
pub struct McpArgs {
    /// Base URL of the running lancer-api instance.
    #[arg(long, default_value = "http://127.0.0.1:9191")]
    api: String,
}

struct Tool {
    name: &'static str,
    description: &'static str,
    method: &'static str, // GET | POST
    path: &'static str,
    /// JSON-schema property names (all optional strings/objects) for inputSchema.
    props: &'static [(&'static str, &'static str)],
}

const TOOLS: &[Tool] = &[
    Tool { name: "history_list", description: "List captured proxy HTTP history.", method: "GET", path: "/v1/history", props: &[("limit", "number")] },
    Tool { name: "issues_list", description: "List stored scan issues.", method: "GET", path: "/v1/issues", props: &[] },
    Tool { name: "repeater_send", description: "Send a raw HTTP request and return the response.", method: "POST", path: "/v1/repeater", props: &[("request", "string"), ("scheme", "string"), ("host", "string"), ("port", "number")] },
    Tool { name: "scan_active", description: "Run an active vulnerability scan on a raw request.", method: "POST", path: "/v1/scan/active", props: &[("request", "string"), ("scheme", "string")] },
    Tool { name: "scan_passive", description: "Run a passive scan on a URL.", method: "POST", path: "/v1/scan/passive", props: &[("url", "string")] },
    Tool { name: "intruder", description: "Run an Intruder attack (sniper/clusterbomb/etc.).", method: "POST", path: "/v1/intruder", props: &[("request", "string"), ("kind", "string"), ("payloads", "array")] },
    Tool { name: "collaborator_generate", description: "Allocate a fresh OAST/Collaborator payload host.", method: "POST", path: "/v1/collaborator/generate", props: &[] },
    Tool { name: "collaborator_interactions", description: "List recorded OAST interactions.", method: "GET", path: "/v1/collaborator/interactions", props: &[] },
    Tool { name: "transform", description: "Encode/decode/hash data (base64, url, hex, sha256, …).", method: "POST", path: "/v1/transform", props: &[("input", "string"), ("op", "string")] },
    Tool { name: "mass_fuzz", description: "Run a high-speed content/parameter fuzz (FUZZ marker).", method: "POST", path: "/v1/massfuzz", props: &[("url", "string"), ("words", "array")] },
    Tool { name: "dual_session_replay", description: "Replay a request under two sessions to detect IDOR/access-control flaws.", method: "POST", path: "/v1/replay/dual", props: &[("request", "string"), ("session_a", "object"), ("session_b", "object")] },
    Tool { name: "id_fuzz", description: "Detect and mutate ID values in a request to find IDOR.", method: "POST", path: "/v1/replay/idfuzz", props: &[("request", "string")] },
    Tool { name: "flow_graph", description: "Build the application navigation graph from proxy history.", method: "GET", path: "/v1/replay/flowgraph", props: &[] },
    Tool { name: "report", description: "Render a findings report (format=markdown|json|html|sarif).", method: "GET", path: "/v1/report", props: &[("format", "string")] },
    Tool { name: "import_spec", description: "Import an OpenAPI/Postman/GraphQL spec into requests.", method: "POST", path: "/v1/scan/import-spec", props: &[("spec", "string")] },
];

fn tools_schema() -> Value {
    let arr: Vec<Value> = TOOLS.iter().map(|t| {
        let mut properties = serde_json::Map::new();
        for (k, ty) in t.props {
            properties.insert((*k).to_string(), json!({ "type": ty }));
        }
        json!({
            "name": t.name,
            "description": t.description,
            "inputSchema": { "type": "object", "properties": properties },
        })
    }).collect();
    json!(arr)
}

async fn call_tool(client: &HttpClient, api: &str, name: &str, args: &Value) -> Result<String> {
    let Some(tool) = TOOLS.iter().find(|t| t.name == name) else {
        return Ok(format!("unknown tool: {name}"));
    };
    let url = if tool.method == "GET" {
        // Append scalar args as query params.
        let mut q = String::new();
        if let Some(obj) = args.as_object() {
            for (k, v) in obj {
                let val = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                q.push_str(if q.is_empty() { "?" } else { "&" });
                q.push_str(&format!("{k}={val}"));
            }
        }
        format!("{api}{}{q}", tool.path)
    } else {
        format!("{api}{}", tool.path)
    };

    let mut req = HttpRequest::builder(tool.method, &url)?;
    if tool.method == "POST" {
        req.set_header("content-type", "application/json");
        req.body = bytes::Bytes::from(serde_json::to_vec(args).unwrap_or_default());
    }
    let resp = client.send(&req).await?;
    Ok(resp.body_text().unwrap_or("").to_string())
}

pub async fn run(args: McpArgs) -> Result<()> {
    let client = HttpClient::new();
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = reader.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(line) else { continue };
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");

        // Notifications (no id) get no response.
        let response: Option<Value> = match method {
            "initialize" => Some(json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "lancer", "version": env!("CARGO_PKG_VERSION") },
                }
            })),
            "tools/list" => Some(json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "tools": tools_schema() }
            })),
            "tools/call" => {
                let params = msg.get("params").cloned().unwrap_or(json!({}));
                let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
                let (text, is_error) = match call_tool(&client, &args.api, name, &arguments).await {
                    Ok(t) => (t, false),
                    Err(e) => (format!("error: {e} (is lancer-api running at {}?)", args.api), true),
                };
                Some(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "content": [{ "type": "text", "text": text }], "isError": is_error }
                }))
            }
            "ping" => Some(json!({ "jsonrpc": "2.0", "id": id, "result": {} })),
            // notifications/initialized and other notifications: no reply.
            _ if id.is_none() => None,
            _ => Some(json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32601, "message": format!("method not found: {method}") }
            })),
        };

        if let Some(r) = response {
            let mut out = serde_json::to_vec(&r).unwrap_or_default();
            out.push(b'\n');
            stdout.write_all(&out).await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}
