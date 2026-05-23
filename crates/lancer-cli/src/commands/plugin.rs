//! `lancer plugin` — manage installed plugins.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use lancer_plugin::PluginRegistry;

#[derive(Debug, Args)]
pub struct PluginArgs {
    #[command(subcommand)]
    cmd: PluginCmd,
}

#[derive(Debug, Subcommand)]
enum PluginCmd {
    List {
        #[arg(long, default_value = "./plugins")]
        dir: PathBuf,
    },
    Load {
        manifest: PathBuf,
    },
}

pub async fn run(args: PluginArgs) -> Result<()> {
    let reg = PluginRegistry::new();
    match args.cmd {
        PluginCmd::List { dir } => {
            reg.load_directory(&dir)?;
            for p in reg.list() {
                println!(
                    "{:24} {:>10}  {}",
                    p.manifest.id, p.manifest.version, p.manifest.name
                );
            }
        }
        PluginCmd::Load { manifest } => {
            reg.load_one(&manifest)?;
            println!("loaded");
        }
    }
    Ok(())
}
