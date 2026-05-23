//! `lancer organizer` — manage the saved-request library.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use lancer_storage::{OrganizerEntry, Storage};
use lancer_tools::organizer_tools::{OrganizerTools, SaveSpec};

#[derive(Debug, Args)]
pub struct OrganizerArgs {
    #[arg(long)]
    project: PathBuf,
    #[command(subcommand)]
    cmd: OrganizerCmd,
}

#[derive(Debug, Subcommand)]
enum OrganizerCmd {
    /// List saved items.
    List {
        #[arg(long)]
        tag: Option<String>,
    },
    /// Save a raw request to the organizer.
    Save {
        request: String,
        #[arg(long)]
        title: String,
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long, default_value = "https")]
        scheme: String,
    },
    Search {
        q: String,
    },
}

pub async fn run(args: OrganizerArgs) -> Result<()> {
    let storage = Storage::open(args.project).await?;
    let tools = OrganizerTools::new(storage.organizer());
    match args.cmd {
        OrganizerCmd::List { tag } => {
            let items: Vec<OrganizerEntry> = match tag {
                Some(t) => tools.list_by_tag(&t).await?,
                None => storage.organizer().list().await?,
            };
            for it in items {
                println!(
                    "{} [{}] {} ({} tags)",
                    it.added_at.format("%Y-%m-%d %H:%M"),
                    it.id,
                    it.title,
                    it.tags.len()
                );
            }
        }
        OrganizerCmd::Save { request, title, tags, notes, scheme } => {
            let raw = if request == "-" {
                use std::io::Read;
                let mut b = Vec::new();
                std::io::stdin().read_to_end(&mut b)?;
                b
            } else {
                std::fs::read(&request)?
            };
            let mut req = lancer_core::HttpRequest::parse_wire(&raw)?;
            req.meta.scheme = scheme;
            let id = tools
                .save(SaveSpec { title: &title, tags, notes }, req, None)
                .await?;
            println!("{id}");
        }
        OrganizerCmd::Search { q } => {
            for it in tools.search(&q).await? {
                println!("{} {}", it.id, it.title);
            }
        }
    }
    Ok(())
}
