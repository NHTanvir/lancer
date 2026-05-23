//! `lancer bcheck` — load a BCheck library and run against a request.

use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use lancer_core::HttpRequest;
use lancer_scanner::bcheck::{BCheck, BCheckLibrary};
use lancer_tools::HttpClient;

#[derive(Debug, Args)]
pub struct BCheckArgs {
    #[command(subcommand)]
    cmd: BCheckCmd,
}

#[derive(Debug, Subcommand)]
enum BCheckCmd {
    /// List BChecks discovered under a directory.
    List {
        #[arg(long, default_value = "./bchecks")]
        dir: PathBuf,
    },
    /// Validate a single BCheck file.
    Lint {
        file: PathBuf,
    },
    /// Run a BCheck against a raw request.
    Run {
        check: PathBuf,
        request: String,
        #[arg(long, default_value = "https")]
        scheme: String,
    },
}

pub async fn run(args: BCheckArgs) -> Result<()> {
    match args.cmd {
        BCheckCmd::List { dir } => {
            let lib = BCheckLibrary::from_dir(&dir)?;
            for c in &lib.checks {
                println!("{} — {} [{}]", c.id, c.name, c.severity);
            }
            println!("total: {}", lib.checks.len());
        }
        BCheckCmd::Lint { file } => {
            let body = std::fs::read_to_string(&file)?;
            let c = BCheck::parse(&body)?;
            println!("ok: {} probes, severity={}, confidence={}", c.probes.len(), c.severity, c.confidence);
        }
        BCheckCmd::Run { check, request, scheme } => {
            let body = std::fs::read_to_string(&check)?;
            let c = BCheck::parse(&body)?;
            let raw = read_or_stdin(&request)?;
            let mut req = HttpRequest::parse_wire(&raw)?;
            req.meta.scheme = scheme;
            let client = HttpClient::new();
            let issues = c.run(&client, &req).await?;
            if issues.is_empty() {
                println!("no match");
            } else {
                for i in issues {
                    println!("[{}/{}] {} — {}", i.severity.as_str(), i.confidence.as_str(), i.name, i.description);
                }
            }
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
