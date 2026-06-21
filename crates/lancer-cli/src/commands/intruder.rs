//! `lancer intruder` — run an attack defined on the command line.

use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, ValueEnum};
use lancer_core::HttpRequest;
use lancer_tools::{
    HttpClient, Intruder, IntruderConfig, ParsedTemplate, PayloadSet, AttackKind, DEFAULT_MARKER,
};

#[derive(Debug, Args)]
pub struct IntruderArgs {
    /// Raw HTTP/1.1 request file (use `-` for stdin) with §…§ payload markers.
    #[arg(long)]
    request: String,
    /// One or more payload sources. Use `file:path/to/list.txt`,
    /// `list:a,b,c`, `num:1-10[:step]`, `brute:abc:1:3`, `null:50`.
    #[arg(long = "payloads")]
    payloads: Vec<String>,
    /// Attack type.
    #[arg(long, value_enum, default_value_t = Kind::Sniper)]
    kind: Kind,
    /// Override scheme.
    #[arg(long, default_value = "https")]
    scheme: String,
    /// Override host:port.
    #[arg(long)]
    target: Option<String>,
    /// Max concurrent in-flight requests.
    #[arg(long, default_value_t = 10)]
    concurrency: usize,
    /// Throttle between requests, ms.
    #[arg(long, default_value_t = 0)]
    throttle_ms: u64,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Kind {
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

pub async fn run(args: IntruderArgs) -> Result<()> {
    let raw = if args.request == "-" {
        let mut s = Vec::new();
        std::io::stdin().read_to_end(&mut s)?;
        s
    } else {
        std::fs::read(PathBuf::from(&args.request))?
    };
    let mut req = HttpRequest::parse_wire(&raw)?;
    req.meta.scheme = args.scheme.clone();
    if let Some(t) = args.target {
        let (h, p) = match t.split_once(':') {
            Some((h, p)) => (h.to_string(), p.parse()?),
            None => (t.clone(), if args.scheme == "https" { 443 } else { 80 }),
        };
        req.meta.host = h;
        req.meta.port = p;
    }

    let sets: Vec<PayloadSet> = args
        .payloads
        .iter()
        .map(|s| parse_set(s))
        .collect::<Result<_>>()?;

    let kind = match args.kind {
        Kind::Sniper => AttackKind::Sniper,
        Kind::BatteringRam => AttackKind::BatteringRam,
        Kind::Pitchfork => AttackKind::Pitchfork,
        Kind::ClusterBomb => AttackKind::ClusterBomb,
    };
    let cfg = IntruderConfig {
        kind,
        max_concurrency: args.concurrency,
        throttle_ms: args.throttle_ms,
        ..Default::default()
    };

    let template = ParsedTemplate::parse(req, DEFAULT_MARKER);
    println!("# positions: {}", template.position_count());
    let intruder = Intruder::new(HttpClient::new(), cfg);
    let results = intruder.run(template, sets).await?;
    println!("idx\tstatus\tlength\ttime_ms\tpayload");
    for r in results {
        let payload = r.payloads.join(",");
        let err = r.error.as_deref().unwrap_or("");
        println!(
            "{}\t{}\t{}\t{}\t{}{}",
            r.index,
            r.status,
            r.length,
            r.time_ms,
            payload,
            if err.is_empty() { String::new() } else { format!(" ERR={err}") }
        );
    }
    Ok(())
}

fn parse_set(s: &str) -> Result<PayloadSet> {
    if let Some(rest) = s.strip_prefix("file:") {
        return Ok(PayloadSet::FromFile { path: PathBuf::from(rest) });
    }
    if let Some(rest) = s.strip_prefix("list:") {
        return Ok(PayloadSet::Simple(
            rest.split(',').map(|x| x.to_string()).collect(),
        ));
    }
    if let Some(rest) = s.strip_prefix("num:") {
        let mut parts = rest.split(':');
        let range = parts.next().unwrap_or("0-0");
        let step: i64 = parts.next().map(|x| x.parse()).transpose()?.unwrap_or(1);
        let (a, b) = range
            .split_once('-')
            .ok_or_else(|| anyhow::anyhow!("bad num range"))?;
        return Ok(PayloadSet::Numbers {
            from: a.parse()?,
            to: b.parse()?,
            step,
        });
    }
    if let Some(rest) = s.strip_prefix("brute:") {
        let mut parts = rest.split(':');
        let charset = parts.next().unwrap_or("abc").to_string();
        let min_len: usize = parts.next().unwrap_or("1").parse()?;
        let max_len: usize = parts.next().unwrap_or("3").parse()?;
        return Ok(PayloadSet::BruteForce { charset, min_len, max_len });
    }
    if let Some(rest) = s.strip_prefix("null:") {
        return Ok(PayloadSet::Null { count: rest.parse()? });
    }
    anyhow::bail!("unrecognized payload set: {s}")
}
