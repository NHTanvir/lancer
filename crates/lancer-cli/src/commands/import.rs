//! `lancer import` — load an OpenAPI 3.x spec or a Postman 2.1 collection.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use lancer_tools::{parse_openapi, parse_postman};

#[derive(Debug, Args)]
pub struct ImportArgs {
    #[command(subcommand)]
    cmd: ImportCmd,
}

#[derive(Debug, Subcommand)]
enum ImportCmd {
    Openapi {
        file: PathBuf,
        #[arg(long)]
        base: Option<String>,
    },
    Postman {
        file: PathBuf,
    },
}

pub async fn run(args: ImportArgs) -> Result<()> {
    let imported = match args.cmd {
        ImportCmd::Openapi { file, base } => {
            let body = std::fs::read_to_string(&file)?;
            parse_openapi(&body, base.as_deref())?
        }
        ImportCmd::Postman { file } => {
            let body = std::fs::read_to_string(&file)?;
            parse_postman(&body)?
        }
    };
    println!("imported {} requests", imported.len());
    for ir in imported {
        println!(
            "  [{}] {} {} {}",
            ir.tags.join(","),
            ir.request.method,
            ir.request.url(),
            ir.name
        );
    }
    Ok(())
}
