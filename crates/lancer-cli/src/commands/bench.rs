//! `lancer bench` — §25 throughput benchmark. Fires N requests at a target with
//! a configurable concurrency cap and reports req/s + latency percentiles, so
//! the "100k+ req/s" performance claim can be measured on real hardware.

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use clap::Args;
use lancer_core::HttpRequest;
use lancer_tools::HttpClient;
use tokio::sync::Semaphore;

#[derive(Debug, Args)]
pub struct BenchArgs {
    /// Target URL.
    url: String,
    /// Total number of requests to send.
    #[arg(short = 'n', long, default_value_t = 1000)]
    requests: usize,
    /// Max concurrent in-flight requests.
    #[arg(short = 'c', long, default_value_t = 50)]
    concurrency: usize,
    /// HTTP method.
    #[arg(short = 'X', long, default_value = "GET")]
    method: String,
}

pub async fn run(args: BenchArgs) -> Result<()> {
    let client = HttpClient::new();
    let sem = Arc::new(Semaphore::new(args.concurrency.max(1)));
    let url = Arc::new(args.url);
    let method = Arc::new(args.method);

    println!(
        "Benchmarking {} — {} requests, {} concurrent…",
        url, args.requests, args.concurrency
    );
    let start = Instant::now();
    let mut handles = Vec::with_capacity(args.requests);
    for _ in 0..args.requests {
        let Ok(permit) = sem.clone().acquire_owned().await else { break };
        let client = client.clone();
        let url = url.clone();
        let method = method.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let t = Instant::now();
            let ok = HttpRequest::builder(method.as_str(), &url)
                .ok()
                .map(|req| async move { client.send(&req).await.is_ok() });
            let ok = match ok {
                Some(fut) => fut.await,
                None => false,
            };
            (ok, t.elapsed().as_secs_f64() * 1000.0)
        }));
    }

    let mut latencies: Vec<f64> = Vec::with_capacity(handles.len());
    let mut ok = 0usize;
    let mut err = 0usize;
    for h in handles {
        if let Ok((success, ms)) = h.await {
            if success { ok += 1 } else { err += 1 }
            latencies.push(ms);
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |p: f64| -> f64 {
        if latencies.is_empty() { return 0.0; }
        let idx = ((latencies.len() as f64 - 1.0) * p).round() as usize;
        latencies[idx]
    };
    let total = ok + err;
    let rps = if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 };

    println!("\n── Results ──");
    println!("  Completed:   {total} ({ok} ok, {err} errors)");
    println!("  Duration:    {elapsed:.2} s");
    println!("  Throughput:  {rps:.0} req/s");
    println!("  Latency p50: {:.1} ms", pct(0.50));
    println!("  Latency p90: {:.1} ms", pct(0.90));
    println!("  Latency p99: {:.1} ms", pct(0.99));
    println!("  Latency max: {:.1} ms", latencies.last().copied().unwrap_or(0.0));
    Ok(())
}
