//! `lancer payloads` — searchable payload encyclopedia.

use anyhow::Result;
use clap::{Args, Subcommand};
use lancer_tools::payload_library::{bundled, search};

#[derive(Debug, Args)]
pub struct PayloadsArgs {
    #[command(subcommand)]
    cmd: PayloadsCmd,
}

#[derive(Debug, Subcommand)]
enum PayloadsCmd {
    List {
        #[arg(long)]
        category: Option<String>,
    },
    Search {
        query: String,
    },
}

pub async fn run(args: PayloadsArgs) -> Result<()> {
    let lib = bundled();
    match args.cmd {
        PayloadsCmd::List { category } => {
            for p in &lib {
                if let Some(c) = &category {
                    if &p.category != c {
                        continue;
                    }
                }
                println!("[{}] {}\n  {}", p.category, p.label, p.payload);
            }
        }
        PayloadsCmd::Search { query } => {
            for p in search(&lib, &query) {
                println!("[{}] {}\n  {}", p.category, p.label, p.payload);
            }
        }
    }
    Ok(())
}
