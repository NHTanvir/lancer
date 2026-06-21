//! `lancer mcp-scan` — §44 MCP Server Scanner.
//!
//! Scans a Model Context Protocol server for tool-poisoning, prompt-injection,
//! rug-pull, cross-server tool collision, and insecure-tool issues.
//!
//! The transport is inferred from the `--server` URI scheme:
//!   stdio://./my-mcp-server   sse://host/path   ws://host/path   http://host/path
//!
//! Example:
//!   lancer mcp-scan --server stdio://./my-mcp-server --depth full

use anyhow::Result;
use clap::{Args, ValueEnum};
use lancer_mcp_scan::{ScanDepth, ScanRequest, Severity, Transport};

#[derive(Debug, Args)]
pub struct McpScanArgs {
    /// MCP server URI. Scheme selects the transport:
    /// stdio://<command>, sse://<url>, ws://<url>, http://<url> (https:// also accepted).
    #[arg(long)]
    server: String,

    /// Scan depth.
    #[arg(long, value_enum, default_value_t = Depth::Full)]
    depth: Depth,

    /// Emit the full ScanResult as pretty JSON instead of a text summary.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Depth {
    Quick,
    Full,
}

impl From<Depth> for ScanDepth {
    fn from(d: Depth) -> Self {
        match d {
            Depth::Quick => ScanDepth::Quick,
            Depth::Full => ScanDepth::Full,
        }
    }
}

pub async fn run(args: McpScanArgs) -> Result<()> {
    let (transport, server) = parse_server(&args.server)?;

    let req = ScanRequest {
        transport,
        server,
        depth: args.depth.into(),
    };

    let result = lancer_mcp_scan::scan(req).await;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    println!("scan {} — server {}", result.id, result.server);
    println!("scanned_at: {}", result.scanned_at.to_rfc3339());
    println!(
        "tools: {}  resources: {}  findings: {}",
        result.tools.len(),
        result.resources.len(),
        result.findings.len()
    );

    if !result.tools.is_empty() {
        println!("\ntools:");
        for t in &result.tools {
            println!("  {} ({})", t.name, t.description_hash);
        }
    }

    if !result.resources.is_empty() {
        println!("\nresources:");
        for r in &result.resources {
            println!("  {}{}", r.uri, r.name.as_deref().map(|n| format!(" — {n}")).unwrap_or_default());
        }
    }

    if result.findings.is_empty() {
        println!("\nno findings");
    } else {
        println!("\nfindings:");
        for f in &result.findings {
            let tool = f.tool.as_deref().unwrap_or("-");
            println!("  [{}/{}] {} ({}) — {}", severity_str(f.severity), f.category, tool, f.id, f.message);
            if let Some(ev) = &f.evidence {
                println!("    evidence: {ev}");
            }
        }
    }

    Ok(())
}

/// Split a `<scheme>://<rest>` URI into a transport + the value the crate expects.
///
/// For stdio the crate treats `server` as a command line (`./binary --flag`), so we
/// strip the `stdio://` prefix. For network transports we hand the crate a full URL.
fn parse_server(uri: &str) -> Result<(Transport, String)> {
    if let Some(rest) = uri.strip_prefix("stdio://") {
        Ok((Transport::Stdio, rest.to_string()))
    } else if let Some(rest) = uri.strip_prefix("sse://") {
        // Hand the underlying JSON-RPC client an http URL.
        Ok((Transport::Sse, format!("http://{rest}")))
    } else if let Some(rest) = uri.strip_prefix("sses://") {
        // TLS-secured SSE endpoint.
        Ok((Transport::Sse, format!("https://{rest}")))
    } else if let Some(rest) = uri.strip_prefix("ws://") {
        Ok((Transport::WebSocket, format!("ws://{rest}")))
    } else if let Some(rest) = uri.strip_prefix("wss://") {
        Ok((Transport::WebSocket, format!("wss://{rest}")))
    } else if uri.starts_with("http://") || uri.starts_with("https://") {
        Ok((Transport::Http, uri.to_string()))
    } else {
        anyhow::bail!(
            "unsupported server scheme in `{uri}` — expected one of stdio://, sse://, sses://, ws://, wss://, http://, https://"
        )
    }
}

fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
