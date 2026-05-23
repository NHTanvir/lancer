use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use lancer_storage::{HistoryFilter, Storage};

#[derive(Debug, Args)]
pub struct HistoryArgs {
    #[arg(long)]
    project: PathBuf,
    #[command(subcommand)]
    cmd: HistoryCmd,
}

#[derive(Debug, Subcommand)]
enum HistoryCmd {
    /// List recent history rows.
    List {
        #[arg(long, default_value_t = 25)]
        limit: i64,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        method: Option<String>,
        #[arg(long)]
        status: Option<u16>,
    },
    /// Show a single row in detail.
    Show {
        id: String,
    },
    /// Clear all history rows.
    Clear,
}

pub async fn run(args: HistoryArgs) -> Result<()> {
    let storage = Storage::open(args.project).await?;
    let history = storage.history();
    match args.cmd {
        HistoryCmd::List { limit, host, method, status } => {
            let filter = HistoryFilter {
                host,
                method,
                status,
                limit: Some(limit),
                ..Default::default()
            };
            let rows = history.list(&filter).await?;
            for r in rows {
                println!(
                    "{} {:>4} {:>4} {:7} {:>5} {}://{}{}",
                    r.captured_at.format("%H:%M:%S"),
                    r.status.unwrap_or(0),
                    r.response_length.unwrap_or(0),
                    r.method,
                    r.port,
                    r.scheme,
                    r.host,
                    r.path
                );
            }
        }
        HistoryCmd::Show { id } => {
            let uuid = uuid::Uuid::parse_str(&id)?;
            match history.get(uuid).await? {
                Some(rec) => {
                    println!("{}", serde_json::to_string_pretty(&rec)?);
                }
                None => println!("not found"),
            }
        }
        HistoryCmd::Clear => {
            history.clear().await?;
            println!("history cleared");
        }
    }
    Ok(())
}
