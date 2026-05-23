use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use lancer_core::project::ProjectMeta;
use lancer_storage::Storage;

#[derive(Debug, Args)]
pub struct ProjectArgs {
    #[command(subcommand)]
    cmd: ProjectCmd,
}

#[derive(Debug, Subcommand)]
enum ProjectCmd {
    /// Create a new on-disk project file.
    New {
        #[arg(long)]
        path: PathBuf,
        #[arg(long, default_value = "untitled")]
        name: String,
    },
    /// Print project metadata.
    Info {
        #[arg(long)]
        path: PathBuf,
    },
}

pub async fn run(args: ProjectArgs) -> Result<()> {
    match args.cmd {
        ProjectCmd::New { path, name } => {
            let storage = Storage::open(&path).await?;
            let meta = ProjectMeta::on_disk(name, &path);
            storage.project_store().upsert(&meta).await?;
            println!("created {}", path.display());
        }
        ProjectCmd::Info { path } => {
            let storage = Storage::open(&path).await?;
            match storage.project_store().load().await? {
                Some(meta) => println!("{}", serde_json::to_string_pretty(&meta)?),
                None => println!("(no metadata)"),
            }
        }
    }
    Ok(())
}
