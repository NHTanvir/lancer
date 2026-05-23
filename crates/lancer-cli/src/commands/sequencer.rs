//! `lancer sequencer` — analyze a file of one-token-per-line samples.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use lancer_tools::Sequencer;

#[derive(Debug, Args)]
pub struct SequencerArgs {
    /// File with one token per line (raw bytes; if `--hex`, hex-decoded).
    tokens: PathBuf,
    /// Tokens are hex-encoded.
    #[arg(long)]
    hex: bool,
}

pub async fn run(args: SequencerArgs) -> Result<()> {
    let f = std::fs::File::open(&args.tokens)?;
    let r = BufReader::new(f);
    let mut tokens = Vec::new();
    for line in r.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let bytes = if args.hex {
            hex::decode(line)?
        } else {
            line.as_bytes().to_vec()
        };
        tokens.push(bytes);
    }
    let report = Sequencer::analyze(&tokens);
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
