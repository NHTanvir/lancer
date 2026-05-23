//! `lancer export` — emit issue tracker payloads (Jira / Linear / GitHub / DefectDojo).

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, ValueEnum};
use lancer_report::exporters::{defectdojo, faraday_csv, github, jira, linear};
use lancer_storage::Storage;

#[derive(Debug, Args)]
pub struct ExportArgs {
    #[arg(long)]
    project: PathBuf,
    #[arg(long, value_enum)]
    to: Target,
    /// Required for `--to jira`.
    #[arg(long)]
    jira_project: Option<String>,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Target {
    Jira,
    Linear,
    Github,
    Defectdojo,
    Faraday,
}

pub async fn run(args: ExportArgs) -> Result<()> {
    let storage = Storage::open(&args.project).await?;
    let issues = storage.issues().list().await?;
    let body = match args.to {
        Target::Jira => {
            let key = args.jira_project.unwrap_or_else(|| "LANCER".into());
            serde_json::to_string_pretty(&jira(&key, &issues))?
        }
        Target::Linear => serde_json::to_string_pretty(&linear(&issues))?,
        Target::Github => serde_json::to_string_pretty(&github(&issues))?,
        Target::Defectdojo => serde_json::to_string_pretty(&defectdojo(&issues))?,
        Target::Faraday => faraday_csv(&issues),
    };
    match args.out {
        Some(p) => {
            std::fs::write(&p, body)?;
            println!("wrote {}", p.display());
        }
        None => println!("{body}"),
    }
    Ok(())
}
