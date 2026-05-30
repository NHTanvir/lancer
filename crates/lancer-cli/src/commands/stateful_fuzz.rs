//! `lancer stateful-fuzz` — §48 Stateful API fuzzer (RESTler equivalent).
//!
//! Reads an OpenAPI/Swagger spec, infers stateful request sequences, and probes
//! the target for state flaws (access-control faults, use-after-free, workflow
//! skips, server errors). Calls `lancer-stateful-fuzz` directly.
//!
//! Example:
//!   `lancer stateful-fuzz --spec openapi.json --base-url https://api.example.com --auth-token <token>`

use std::io::Read;

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use lancer_stateful_fuzz::{run_fuzz, FuzzMode, FuzzRequest};

#[derive(Debug, Args)]
pub struct StatefulFuzzArgs {
    /// Path to the OpenAPI/Swagger spec (JSON or YAML). Use `-` to read from stdin.
    #[arg(long)]
    spec: String,

    /// Base URL of the target API the sequences are replayed against.
    #[arg(long)]
    base_url: String,

    /// Bearer/authorization header value sent with every request.
    #[arg(long)]
    auth_token: Option<String>,

    /// Fuzzing strategy.
    #[arg(long, value_enum, default_value_t = Mode::Sequence)]
    mode: Mode,

    /// Maximum number of inferred sequences to execute.
    #[arg(long, default_value_t = 50)]
    max_sequences: usize,

    /// Emit the full session as pretty JSON instead of a text summary.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Mode {
    ProductionSafe,
    Sequence,
    ClusterBomb,
    MutateMidSequence,
}

impl From<Mode> for FuzzMode {
    fn from(m: Mode) -> Self {
        match m {
            Mode::ProductionSafe => FuzzMode::ProductionSafe,
            Mode::Sequence => FuzzMode::Sequence,
            Mode::ClusterBomb => FuzzMode::ClusterBomb,
            Mode::MutateMidSequence => FuzzMode::MutateMidSequence,
        }
    }
}

pub async fn run(args: StatefulFuzzArgs) -> Result<()> {
    let spec = read_or_stdin(&args.spec)?;

    let req = FuzzRequest {
        spec,
        base_url: args.base_url,
        auth_token: args.auth_token,
        mode: args.mode.into(),
        max_sequences: args.max_sequences,
    };

    let session = run_fuzz(req)
        .await
        .map_err(|e| anyhow::anyhow!("stateful fuzz failed: {e}"))?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&session)?);
        return Ok(());
    }

    println!("session {}", session.id);
    println!("operations discovered: {}", session.ops.len());
    println!("sequences run:         {}", session.sequences_run);
    println!("flaws found:           {}", session.flaws.len());

    if session.flaws.is_empty() {
        println!("\nno state flaws detected");
        return Ok(());
    }

    println!("\nflaws:");
    for f in &session.flaws {
        println!(
            "  [{:?}/{:?}] step {} — {}",
            f.severity, f.kind, f.at_step, f.message
        );
        let path: Vec<String> = f
            .sequence
            .ops
            .iter()
            .map(|o| format!("{} {}", o.method, o.path))
            .collect();
        println!("    sequence: {}", path.join(" -> "));
    }

    Ok(())
}

fn read_or_stdin(path: &str) -> Result<String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("reading spec from stdin")?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path).with_context(|| format!("reading spec file {path}"))
    }
}
