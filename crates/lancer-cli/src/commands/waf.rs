//! `lancer waf detect <url>` — fingerprint the WAF in front of a target.

use anyhow::Result;
use clap::Args;
use lancer_core::HttpRequest;
use lancer_scanner::waf::detect;
use lancer_tools::HttpClient;

#[derive(Debug, Args)]
pub struct WafArgs {
    url: String,
}

pub async fn run(args: WafArgs) -> Result<()> {
    let req = HttpRequest::builder("GET", &args.url)?;
    let resp = HttpClient::new().send(&req).await?;
    let hits = detect(&resp);
    if hits.is_empty() {
        println!("no WAF detected");
        return Ok(());
    }
    for h in hits {
        println!("WAF: {}", h.name);
        for s in &h.matched_signals {
            println!("  signal: {s}");
        }
        for n in &h.bypass_notes {
            println!("  hint: {n}");
        }
    }
    Ok(())
}
