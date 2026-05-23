//! `lancer repeater` — read a raw HTTP request from a file or stdin, send it,
//! print the response.

use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use lancer_core::HttpRequest;
use lancer_tools::HttpClient;

#[derive(Debug, Args)]
pub struct RepeaterArgs {
    /// Raw HTTP/1.1 request file (use `-` for stdin).
    #[arg(long)]
    request: String,
    /// Override scheme (http or https). Required when the request doesn't have
    /// one inferable from headers.
    #[arg(long, default_value = "https")]
    scheme: String,
    /// Override host:port if not derivable from the Host header.
    #[arg(long)]
    target: Option<String>,
    /// Print only the status + headers, omit the response body.
    #[arg(long)]
    head_only: bool,
}

pub async fn run(args: RepeaterArgs) -> Result<()> {
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
            None => {
                let port: u16 = if args.scheme == "https" { 443 } else { 80 };
                (t.clone(), port)
            }
        };
        req.meta.host = h;
        req.meta.port = p;
    } else if req.meta.port == 0 {
        req.meta.port = if args.scheme == "https" { 443 } else { 80 };
    }
    let client = HttpClient::new();
    let resp = client.send(&req).await?;
    println!(
        "HTTP/1.1 {} {}",
        resp.status,
        resp.reason
    );
    for h in &resp.headers {
        println!("{}: {}", h.name, h.value);
    }
    if !args.head_only {
        println!();
        if let Some(text) = resp.body_text() {
            println!("{text}");
        } else {
            println!("<binary {} bytes>", resp.body.len());
        }
    }
    Ok(())
}
