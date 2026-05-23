//! `lancer iac` — parse Dockerfile / docker-compose / k8s / Terraform for
//! additional attack surface.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use lancer_iac::{parse_compose, parse_dockerfile, parse_kubernetes, parse_terraform};

#[derive(Debug, Args)]
pub struct IacArgs {
    #[command(subcommand)]
    cmd: IacCmd,
}

#[derive(Debug, Subcommand)]
enum IacCmd {
    Dockerfile { file: PathBuf },
    Compose { file: PathBuf },
    K8s { file: PathBuf },
    Terraform { file: PathBuf },
}

pub async fn run(args: IacArgs) -> Result<()> {
    let surface = match args.cmd {
        IacCmd::Dockerfile { file } => parse_dockerfile(&std::fs::read_to_string(file)?),
        IacCmd::Compose { file } => parse_compose(&std::fs::read_to_string(file)?)?,
        IacCmd::K8s { file } => parse_kubernetes(&std::fs::read_to_string(file)?)?,
        IacCmd::Terraform { file } => parse_terraform(&std::fs::read_to_string(file)?),
    };
    println!("{}", serde_json::to_string_pretty(&surface)?);
    Ok(())
}
