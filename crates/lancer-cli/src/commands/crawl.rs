//! `lancer crawl` — BFS crawl an entry URL and emit the resulting site-map.

use std::sync::Arc;

use anyhow::Result;
use clap::Args;
use lancer_core::scope::Scope;
use lancer_core::sitemap::SiteMap;
use lancer_tools::{CrawlConfig, Crawler, HttpClient};
use parking_lot::RwLock;

#[derive(Debug, Args)]
pub struct CrawlArgs {
    /// Entry URL.
    url: String,
    #[arg(long, default_value_t = 4)]
    max_depth: usize,
    #[arg(long, default_value_t = 250)]
    max_pages: usize,
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
    #[arg(long, default_value_t = 0)]
    throttle_ms: u64,
    #[arg(long)]
    include_scripts: bool,
    #[arg(long)]
    follow_subdomains: bool,
}

pub async fn run(args: CrawlArgs) -> Result<()> {
    let cfg = CrawlConfig {
        max_depth: args.max_depth,
        max_pages: args.max_pages,
        concurrency: args.concurrency,
        throttle_ms: args.throttle_ms,
        include_scripts: args.include_scripts,
        follow_subdomains: args.follow_subdomains,
    };
    let scope = Arc::new(RwLock::new({
        let mut s = Scope::default();
        s.default_include = true;
        s
    }));
    let crawler = Crawler::new(HttpClient::new(), cfg, scope);
    let sink: Arc<RwLock<SiteMap>> = Arc::new(RwLock::new(SiteMap::new()));
    let pages = crawler.run(&args.url, sink.clone()).await?;
    let sm = sink.read();
    println!(
        "crawled {pages} pages — {} hosts, {} endpoints",
        sm.host_count(),
        sm.endpoint_count()
    );
    for (host, path, ep) in sm.flatten() {
        println!(
            "  [{kind}] {method:7} {host}{path}{status}",
            kind = match ep.kind {
                lancer_core::sitemap::NodeKind::Requested => "got",
                lancer_core::sitemap::NodeKind::Inferred => "inf",
            },
            method = ep.method,
            host = host,
            path = path,
            status = ep
                .status
                .map(|s| format!(" -> {s}"))
                .unwrap_or_default(),
        );
    }
    Ok(())
}
