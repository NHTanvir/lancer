//! `lancer shodan` — §45 Shodan host enrichment.
//!
//! Wraps the `lancer-shodan` REST client. Reads `SHODAN_API_KEY` from the
//! environment (via `ShodanClient::from_env`); when no key is set, `host`
//! falls back to the free InternetDB endpoint. Calls the crate directly —
//! no HTTP round-trip through `lancer-api`.

use anyhow::Result;
use clap::{Args, Subcommand};
use lancer_shodan::ShodanClient;

#[derive(Debug, Args)]
pub struct ShodanArgs {
    #[command(subcommand)]
    cmd: ShodanCmd,
}

#[derive(Debug, Subcommand)]
enum ShodanCmd {
    /// Enrich a single host by IP (Shodan with InternetDB fallback).
    Host {
        /// Target IP address, e.g. `8.8.8.8`.
        ip: String,
        /// Emit raw JSON instead of a human-readable summary.
        #[arg(long)]
        json: bool,
    },
    /// Look up a CVE by ID (e.g. `CVE-2021-44228`).
    Cve {
        /// CVE identifier.
        id: String,
        /// Emit raw JSON instead of a human-readable summary.
        #[arg(long)]
        json: bool,
    },
    /// Search Shodan for hosts matching a query (requires `SHODAN_API_KEY`).
    Search {
        /// Shodan search query, e.g. `apache port:443`.
        query: String,
        /// Result page (Shodan paginates 100 results per page).
        #[arg(long, default_value_t = 1)]
        page: usize,
        /// Emit raw JSON instead of a human-readable summary.
        #[arg(long)]
        json: bool,
    },
}

pub async fn run(args: ShodanArgs) -> Result<()> {
    let client = ShodanClient::from_env();
    match args.cmd {
        ShodanCmd::Host { ip, json } => match client.host(&ip).await {
            Some(info) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&info)?);
                } else {
                    print_host(&info);
                }
            }
            None => anyhow::bail!("no data for host {ip}"),
        },
        ShodanCmd::Cve { id, json } => match client.cve(&id).await {
            Some(info) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&info)?);
                } else {
                    print_cve(&info);
                }
            }
            None => anyhow::bail!("no data for {id}"),
        },
        ShodanCmd::Search { query, page, json } => match client.search(&query, page).await {
            Some(hosts) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&hosts)?);
                } else if hosts.is_empty() {
                    println!("no results");
                } else {
                    for h in &hosts {
                        print_host(h);
                        println!();
                    }
                    println!("{} result(s)", hosts.len());
                }
            }
            None => anyhow::bail!(
                "search failed (a SHODAN_API_KEY is required for search, and the query must be valid)"
            ),
        },
    }
    Ok(())
}

fn print_host(info: &lancer_shodan::HostInfo) {
    println!("host {} [{:?}]", info.ip, info.source);
    if let Some(org) = &info.org {
        println!("  org:       {org}");
    }
    if let Some(country) = &info.country {
        println!("  country:   {country}");
    }
    if let Some(os) = &info.os {
        println!("  os:        {os}");
    }
    if !info.hostnames.is_empty() {
        println!("  hostnames: {}", info.hostnames.join(", "));
    }
    if !info.ports.is_empty() {
        let ports: Vec<String> = info.ports.iter().map(|p| p.to_string()).collect();
        println!("  ports:     {}", ports.join(", "));
    }
    if !info.tags.is_empty() {
        println!("  tags:      {}", info.tags.join(", "));
    }
    if !info.vulns.is_empty() {
        println!("  vulns:     {}", info.vulns.join(", "));
    }
    if let Some(last) = &info.last_update {
        println!("  updated:   {last}");
    }
    println!("  fetched:   {}", info.fetched_at.to_rfc3339());
}

fn print_cve(info: &lancer_shodan::CveInfo) {
    println!("{}", info.cve);
    if let Some(summary) = &info.summary {
        println!("  summary:  {summary}");
    }
    if let Some(cvss) = info.cvss {
        println!("  cvss:     {cvss}");
    }
    if let Some(cvss_v3) = info.cvss_v3 {
        println!("  cvss_v3:  {cvss_v3}");
    }
    if let Some(epss) = info.epss {
        println!("  epss:     {epss}");
    }
    println!("  kev:      {}", info.kev);
    if !info.references.is_empty() {
        println!("  references:");
        for r in &info.references {
            println!("    {r}");
        }
    }
}
