//! `lancer cms-scan` — §50 CMS-aware scanner (WordPress / Joomla / Drupal).
//!
//! Detects the CMS powering a target, then runs version detection,
//! known-leak endpoint probes, optional plugin enumeration, and CVE matching.
//!
//!   lancer cms-scan https://target.com
//!   lancer cms-scan https://target.com --enumerate-plugins --json

use anyhow::Result;
use clap::Args;
use lancer_cms::{CmsFinding, CmsScanRequest, CmsScanResult};

#[derive(Debug, Args)]
pub struct CmsScanArgs {
    /// Base URL of the target site (e.g. https://target.com).
    url: String,

    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 15)]
    timeout: u64,

    /// Bruteforce common plugin/theme directories (noisy — authorize first).
    #[arg(long)]
    enumerate_plugins: bool,

    /// Emit the full result as pretty JSON instead of human-readable text.
    #[arg(long)]
    json: bool,
}

pub async fn run(args: CmsScanArgs) -> Result<()> {
    let req = CmsScanRequest {
        target: args.url,
        timeout_secs: args.timeout,
        enumerate_plugins: args.enumerate_plugins,
    };

    let result = lancer_cms::scan(req)
        .await
        .map_err(|e| anyhow::anyhow!("cms scan failed: {e}"))?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_result(&result);
    }
    Ok(())
}

fn print_result(r: &CmsScanResult) {
    println!("target:  {}", r.target);
    println!("cms:     {:?}", r.cms);
    println!("version: {}", r.version.as_deref().unwrap_or("unknown"));

    if !r.plugins.is_empty() {
        println!("plugins: {}", r.plugins.join(", "));
    }
    if !r.themes.is_empty() {
        println!("themes:  {}", r.themes.join(", "));
    }

    if r.findings.is_empty() {
        println!("\nno findings");
    } else {
        println!("\n{} finding(s):", r.findings.len());
        for f in &r.findings {
            print_finding(f);
        }
    }
}

fn print_finding(f: &CmsFinding) {
    println!("\n[{:?}] {}", f.severity, f.title);
    println!("  {}", f.detail);
    if let Some(cve) = &f.cve {
        println!("  cve: {cve}");
    }
    if let Some(url) = &f.evidence_url {
        println!("  evidence: {url}");
    }
}
