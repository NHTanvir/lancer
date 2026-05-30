//! `lancer llm-scan` — §42 LLM vulnerability scanner (garak-equivalent probes).
//!
//! Runs adversarial probe families against an OpenAI-compatible chat-completions
//! endpoint and reports per-probe pass/fail/inconclusive + severity.
//!
//! Calls the `lancer-llm-scan` crate directly (no HTTP), mirroring the
//! `/v1/llm-scan/run` and `/v1/llm-scan/estimate` route handlers.
//!
//!   lancer llm-scan --target https://api.example.com/chat --probes prompt_injection,jailbreak
//!   lancer llm-scan estimate --target https://api.example.com/chat --probes jailbreak
//!   lancer llm-scan list-probes

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use lancer_llm_scan::{
    estimate_cost, probe_catalog, run_scan, ProbeCategory, ScanRequest, Verdict,
};

#[derive(Debug, Args)]
pub struct LlmScanArgs {
    #[command(subcommand)]
    cmd: Option<LlmScanCmd>,

    /// Common scan options used when no subcommand is given (the default `run` action).
    #[command(flatten)]
    run: RunArgs,
}

#[derive(Debug, Subcommand)]
enum LlmScanCmd {
    /// Run the selected probes against the target (default action).
    Run(RunArgs),
    /// Estimate token usage and rough USD cost without calling the target.
    Estimate(RunArgs),
    /// List the available probe categories and individual probes.
    ListProbes {
        /// Emit the catalog as JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Args, Default)]
struct RunArgs {
    /// Chat-completions URL, e.g. https://api.openai.com/v1/chat/completions
    #[arg(long)]
    target: Option<String>,

    /// Comma-separated probe categories to run (default: all). e.g.
    /// prompt_injection,jailbreak,data_leakage
    #[arg(long, value_delimiter = ',')]
    probes: Vec<String>,

    /// API key sent as `Authorization: Bearer <key>`.
    #[arg(long)]
    api_key: Option<String>,

    /// Model name to request (default: gpt-4o-mini).
    #[arg(long)]
    model: Option<String>,

    /// Number of probes to run concurrently.
    #[arg(long, default_value_t = 4)]
    concurrency: usize,

    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,

    /// Emit results as JSON instead of human-readable text.
    #[arg(long)]
    json: bool,
}

pub async fn run(args: LlmScanArgs) -> Result<()> {
    match args.cmd {
        Some(LlmScanCmd::Run(a)) => run_scan_action(a).await,
        Some(LlmScanCmd::Estimate(a)) => estimate_action(a),
        Some(LlmScanCmd::ListProbes { json }) => list_probes(json),
        None => run_scan_action(args.run).await,
    }
}

fn build_request(a: &RunArgs) -> Result<ScanRequest> {
    let target = a
        .target
        .clone()
        .context("--target <url> is required")?;
    let categories = parse_categories(&a.probes)?;
    Ok(ScanRequest {
        target,
        api_key: a.api_key.clone(),
        model: a.model.clone(),
        categories,
        concurrency: a.concurrency,
        timeout_secs: a.timeout_secs,
    })
}

async fn run_scan_action(a: RunArgs) -> Result<()> {
    let req = build_request(&a)?;
    let json = a.json;
    let results = run_scan(req).await;

    if json {
        println!("{}", serde_json::to_string_pretty(&results)?);
        return Ok(());
    }

    if results.is_empty() {
        println!("no probes ran (check --target / --probes)");
        return Ok(());
    }

    let mut fails = 0usize;
    let mut inconclusive = 0usize;
    for r in &results {
        let mark = match r.verdict {
            Verdict::Pass => "PASS",
            Verdict::Fail => {
                fails += 1;
                "FAIL"
            }
            Verdict::Inconclusive => {
                inconclusive += 1;
                "INCONCLUSIVE"
            }
        };
        println!(
            "[{mark}] {:?}/{} ({:?}) — {}",
            r.category, r.probe_name, r.severity, r.reason
        );
    }
    println!(
        "\n{} probe(s): {} fail, {} inconclusive, {} pass",
        results.len(),
        fails,
        inconclusive,
        results.len() - fails - inconclusive
    );
    Ok(())
}

fn estimate_action(a: RunArgs) -> Result<()> {
    let req = build_request(&a)?;
    let (tokens, cost) = estimate_cost(&req);
    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "tokens": tokens,
                "cost_usd": cost,
            }))?
        );
    } else {
        println!("estimated tokens: {tokens}");
        println!("estimated cost:   ${cost:.6}");
    }
    Ok(())
}

fn list_probes(json: bool) -> Result<()> {
    let catalog = probe_catalog();
    if json {
        let items: Vec<serde_json::Value> = catalog
            .iter()
            .map(|p| {
                serde_json::json!({
                    "category": p.category,
                    "name": p.name,
                    "severity": p.severity,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }

    println!("categories (use with --probes, comma-separated):");
    for c in CATEGORY_NAMES {
        println!("  {c}");
    }
    println!("\nprobes:");
    for p in &catalog {
        println!("  {:<18} {:<22} {:?}", category_name(p.category), p.name, p.severity);
    }
    Ok(())
}

/// Canonical snake_case names accepted by `--probes`, matching the crate's
/// serde `rename_all = "snake_case"` representation of `ProbeCategory`.
const CATEGORY_NAMES: &[&str] = &[
    "prompt_injection",
    "jailbreak",
    "data_leakage",
    "hallucination",
    "toxicity",
    "bias",
    "code_generation",
    "tool_misuse",
    "prompt_extraction",
    "xml_injection",
];

fn category_name(c: ProbeCategory) -> &'static str {
    match c {
        ProbeCategory::PromptInjection => "prompt_injection",
        ProbeCategory::Jailbreak => "jailbreak",
        ProbeCategory::DataLeakage => "data_leakage",
        ProbeCategory::Hallucination => "hallucination",
        ProbeCategory::Toxicity => "toxicity",
        ProbeCategory::Bias => "bias",
        ProbeCategory::CodeGeneration => "code_generation",
        ProbeCategory::ToolMisuse => "tool_misuse",
        ProbeCategory::PromptExtraction => "prompt_extraction",
        ProbeCategory::XmlInjection => "xml_injection",
    }
}

fn parse_category(name: &str) -> Result<ProbeCategory> {
    // Tolerate hyphens as well as underscores for ergonomics.
    let norm = name.trim().to_lowercase().replace('-', "_");
    let cat = match norm.as_str() {
        "prompt_injection" => ProbeCategory::PromptInjection,
        "jailbreak" => ProbeCategory::Jailbreak,
        "data_leakage" => ProbeCategory::DataLeakage,
        "hallucination" => ProbeCategory::Hallucination,
        "toxicity" => ProbeCategory::Toxicity,
        "bias" => ProbeCategory::Bias,
        "code_generation" => ProbeCategory::CodeGeneration,
        "tool_misuse" => ProbeCategory::ToolMisuse,
        "prompt_extraction" => ProbeCategory::PromptExtraction,
        "xml_injection" => ProbeCategory::XmlInjection,
        other => anyhow::bail!(
            "unknown probe category `{other}` (valid: {})",
            CATEGORY_NAMES.join(", ")
        ),
    };
    Ok(cat)
}

fn parse_categories(names: &[String]) -> Result<Vec<ProbeCategory>> {
    names
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| parse_category(s))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_categories() {
        let cats = parse_categories(&["prompt_injection".into(), "jailbreak".into()]).unwrap();
        assert_eq!(cats.len(), 2);
        assert_eq!(cats[0], ProbeCategory::PromptInjection);
        assert_eq!(cats[1], ProbeCategory::Jailbreak);
    }

    #[test]
    fn tolerates_hyphens() {
        let cats = parse_categories(&["prompt-injection".into()]).unwrap();
        assert_eq!(cats[0], ProbeCategory::PromptInjection);
    }

    #[test]
    fn empty_means_all() {
        assert!(parse_categories(&[]).unwrap().is_empty());
    }

    #[test]
    fn rejects_unknown() {
        assert!(parse_categories(&["nope".into()]).is_err());
    }
}
