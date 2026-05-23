//! `lancer miner` — hidden parameter discovery, authz audits, AuthMatrix.

use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use lancer_core::HttpRequest;
use lancer_tools::auth_matrix::{run as run_matrix, to_markdown, Identity};
use lancer_tools::autorize::{audit, report_to_issue, AutorizeConfig};
use lancer_tools::param_miner::mine;
use lancer_tools::HttpClient;

#[derive(Debug, Args)]
pub struct MinerArgs {
    #[command(subcommand)]
    cmd: MinerCmd,
}

#[derive(Debug, Subcommand)]
enum MinerCmd {
    /// Discover hidden parameters by name-fuzzing.
    Params {
        request: String,
        #[arg(long, default_value = "https")]
        scheme: String,
        #[arg(long, default_value_t = 10)]
        concurrency: usize,
    },
    /// Replay a request as another identity to spot broken access control.
    Authz {
        request: String,
        #[arg(long, default_value = "https")]
        scheme: String,
        #[arg(long)]
        low_priv_cookie: Option<String>,
        #[arg(long)]
        anon: bool,
    },
    /// Build a request × identity authorization matrix.
    Matrix {
        /// Newline-separated raw-request files.
        #[arg(long)]
        requests: PathBuf,
        /// JSON file: [{ "name":"admin", "cookie":"sid=..."}].
        #[arg(long)]
        identities: PathBuf,
        #[arg(long, default_value = "https")]
        scheme: String,
    },
}

pub async fn run(args: MinerArgs) -> Result<()> {
    let client = HttpClient::new();
    match args.cmd {
        MinerCmd::Params { request, scheme, concurrency } => {
            let raw = read_or_stdin(&request)?;
            let mut req = HttpRequest::parse_wire(&raw)?;
            req.meta.scheme = scheme;
            let hits = mine(client, req, concurrency).await?;
            for h in hits {
                println!(
                    "{}: status {} (baseline {}) length {} (baseline {}){}",
                    h.name, h.status, h.baseline_status, h.length, h.baseline_length,
                    if h.reflected { " REFLECTED" } else { "" },
                );
            }
        }
        MinerCmd::Authz { request, scheme, low_priv_cookie, anon } => {
            let raw = read_or_stdin(&request)?;
            let mut req = HttpRequest::parse_wire(&raw)?;
            req.meta.scheme = scheme;
            let cfg = AutorizeConfig {
                low_priv_cookie,
                anon_cookie: if anon { Some(String::new()) } else { None },
            };
            let report = audit(&client, &req, &cfg).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if let Some(issue) = report_to_issue(&req, &report) {
                println!("\n!! {}: {}", issue.name, issue.description);
            }
        }
        MinerCmd::Matrix { requests, identities, scheme } => {
            let req_files: Vec<String> = std::fs::read_to_string(&requests)?
                .lines()
                .filter(|l| !l.is_empty())
                .map(|s| s.to_string())
                .collect();
            let mut reqs = Vec::with_capacity(req_files.len());
            for f in &req_files {
                let raw = std::fs::read(f)?;
                let mut r = HttpRequest::parse_wire(&raw)?;
                r.meta.scheme = scheme.clone();
                reqs.push((f.clone(), r));
            }
            let ids: Vec<Identity> = serde_json::from_str(&std::fs::read_to_string(&identities)?)?;
            let m = run_matrix(&client, &reqs, &ids).await?;
            print!("{}", to_markdown(&m));
        }
    }
    Ok(())
}

fn read_or_stdin(p: &str) -> Result<Vec<u8>> {
    if p == "-" {
        let mut s = Vec::new();
        std::io::stdin().read_to_end(&mut s)?;
        Ok(s)
    } else {
        Ok(std::fs::read(p)?)
    }
}
