//! `lancer engagement` — engagement-tools subcommands.

use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use lancer_core::HttpRequest;
use lancer_storage::Storage;
use lancer_tools::engagement::{
    analyze_target, discover_content, find_anchors, find_comments, find_references, find_scripts,
    generate_csrf_poc, search_across,
};
use lancer_tools::HttpClient;

#[derive(Debug, Args)]
pub struct EngagementArgs {
    #[command(subcommand)]
    cmd: EngagementCmd,
}

#[derive(Debug, Subcommand)]
enum EngagementCmd {
    /// Find comments in an HTML/JS file (or `-` for stdin).
    FindComments {
        #[arg(long, default_value = "")]
        url: String,
        file: String,
    },
    /// Extract referenced script URLs from an HTML file (or `-`).
    FindScripts {
        #[arg(long)]
        base: String,
        file: String,
    },
    /// Extract anchor href URLs from an HTML file (or `-`).
    FindAnchors {
        #[arg(long)]
        base: String,
        file: String,
    },
    /// Generate a self-submitting CSRF PoC HTML page for a raw request.
    CsrfPoc {
        /// Raw HTTP/1.1 request file (or `-` for stdin).
        request: String,
        #[arg(long, default_value = "https")]
        scheme: String,
    },
    /// Forced-browsing: pick a base URL, iterate a wordlist.
    Discover {
        #[arg(long)]
        base: String,
        #[arg(long)]
        wordlist: PathBuf,
        #[arg(long, default_value_t = 25)]
        concurrency: usize,
    },
    /// Search across stored history for a substring.
    Search {
        #[arg(long)]
        project: PathBuf,
        needle: String,
    },
    /// Find captured messages that reference the given URL.
    References {
        #[arg(long)]
        project: PathBuf,
        url: String,
    },
    /// Print a target attack-surface summary.
    Analyze {
        #[arg(long)]
        project: PathBuf,
    },
}

pub async fn run(args: EngagementArgs) -> Result<()> {
    match args.cmd {
        EngagementCmd::FindComments { url, file } => {
            let body = read_or_stdin(&file)?;
            for hit in find_comments(&url, &String::from_utf8_lossy(&body)) {
                println!("{:?}: {}", hit.kind, hit.snippet);
            }
        }
        EngagementCmd::FindScripts { base, file } => {
            let body = read_or_stdin(&file)?;
            for s in find_scripts(&String::from_utf8_lossy(&body), &base) {
                println!("{s}");
            }
        }
        EngagementCmd::FindAnchors { base, file } => {
            let body = read_or_stdin(&file)?;
            for s in find_anchors(&String::from_utf8_lossy(&body), &base) {
                println!("{s}");
            }
        }
        EngagementCmd::CsrfPoc { request, scheme } => {
            let raw = read_or_stdin(&request)?;
            let mut req = HttpRequest::parse_wire(&raw)?;
            req.meta.scheme = scheme;
            let poc = generate_csrf_poc(&req);
            print!("{}", poc.html);
        }
        EngagementCmd::Discover { base, wordlist, concurrency } => {
            let file = std::fs::File::open(&wordlist)?;
            use std::io::{BufRead, BufReader};
            let words: Vec<String> = BufReader::new(file)
                .lines()
                .filter_map(|l| l.ok())
                .filter(|l| !l.is_empty())
                .collect();
            let client = HttpClient::new();
            let hits = discover_content(client, &base, words.into_iter(), concurrency).await?;
            for h in hits {
                println!("{}\t{}\t{}", h.status, h.length, h.url);
            }
        }
        EngagementCmd::Search { project, needle } => {
            let storage = Storage::open(project).await?;
            for hit in search_across(&storage.history(), &needle).await? {
                println!("{hit}");
            }
        }
        EngagementCmd::References { project, url } => {
            let storage = Storage::open(project).await?;
            for id in find_references(&storage.history(), &url).await? {
                println!("{id}");
            }
        }
        EngagementCmd::Analyze { project } => {
            let storage = Storage::open(project).await?;
            let a = analyze_target(&storage.history()).await?;
            println!("{}", serde_json::to_string_pretty(&a)?);
        }
    }
    Ok(())
}

fn read_or_stdin(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        Ok(std::fs::read(path)?)
    }
}
