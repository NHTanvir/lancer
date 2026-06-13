//! `lancer fuzz` — high-speed content/parameter fuzzer (ffuf-equivalent),
//! sharing the same `lancer_tools::mass_fuzz` engine as the GUI Mass Fuzz tab.

use anyhow::Result;
use clap::Args;
use lancer_tools::mass_fuzz::{run, MassFuzzConfig, COMMON_WORDLIST};
use lancer_tools::HttpClient;

#[derive(Debug, Args)]
pub struct FuzzArgs {
    /// Target URL containing the literal marker `FUZZ`, e.g. https://t/FUZZ
    #[arg(short = 'u', long)]
    url: String,
    /// Wordlist file (one entry per line). Omit to use the bundled common list.
    #[arg(short = 'w', long)]
    wordlist: Option<std::path::PathBuf>,
    #[arg(short = 'X', long, default_value = "GET")]
    method: String,
    /// Comma-separated extensions, e.g. .php,.bak
    #[arg(short = 'e', long, default_value = "")]
    extensions: String,
    #[arg(short = 't', long, default_value_t = 40)]
    threads: usize,
    /// Match status codes (comma list); empty = all.
    #[arg(long, default_value = "")]
    mc: String,
    /// Filter (drop) status codes (comma list).
    #[arg(long, default_value = "404")]
    fc: String,
    /// Filter (drop) response sizes (comma list).
    #[arg(long, default_value = "")]
    fs: String,
    /// Recurse into discovered directories up to this depth.
    #[arg(short = 'r', long, default_value_t = 0)]
    recursion: usize,
}

fn nums(s: &str) -> Vec<u16> {
    s.split(',').filter_map(|x| x.trim().parse().ok()).collect()
}
fn sizes(s: &str) -> Vec<usize> {
    s.split(',').filter_map(|x| x.trim().parse().ok()).collect()
}

pub async fn run_cmd(args: FuzzArgs) -> Result<()> {
    if !args.url.contains("FUZZ") {
        anyhow::bail!("url must contain the FUZZ marker");
    }
    let words: Vec<String> = match &args.wordlist {
        Some(p) => std::fs::read_to_string(p)?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
        None => COMMON_WORDLIST.iter().map(|s| s.to_string()).collect(),
    };
    let cfg = MassFuzzConfig {
        url: args.url,
        method: Some(args.method),
        words,
        extensions: args
            .extensions
            .split(',')
            .map(|e| e.trim().to_string())
            .filter(|e| !e.is_empty())
            .collect(),
        concurrency: Some(args.threads),
        match_status: nums(&args.mc),
        filter_status: nums(&args.fc),
        filter_size: sizes(&args.fs),
        max_requests: None,
        recursion_depth: Some(args.recursion),
    };
    let results = run(cfg, HttpClient::new()).await;
    println!("{:<40} {:>5} {:>8} {:>6}", "WORD", "CODE", "SIZE", "TIME");
    for r in &results {
        println!("{:<40} {:>5} {:>8} {:>5}ms", r.word, r.status, r.length, r.time_ms);
    }
    eprintln!("\n{} results", results.len());
    Ok(())
}
