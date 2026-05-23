//! `lancer dom` — DOM-XSS / postMessage / proto-gadget / clobbering scan
//! over a captured JS or HTML body.

use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use lancer_dom::{analyze_js, detect_clobbering, find_gadgets, find_message_endpoints};

#[derive(Debug, Args)]
pub struct DomArgs {
    #[command(subcommand)]
    cmd: DomCmd,
}

#[derive(Debug, Subcommand)]
enum DomCmd {
    /// Source/sink trace for DOM XSS in a JS file.
    Sinks { file: String },
    /// postMessage handlers + senders.
    Messages { file: String },
    /// Library-side prototype-pollution gadgets.
    Gadgets { file: String },
    /// DOM clobbering candidates in an HTML file.
    Clobber { file: String },
}

pub async fn run(args: DomArgs) -> Result<()> {
    match args.cmd {
        DomCmd::Sinks { file } => {
            let body = read_or_stdin(&file)?;
            for h in analyze_js(&String::from_utf8_lossy(&body)) {
                println!("L{}: {:?} -> {:?}\n   {}", h.line, h.source, h.sink, h.snippet);
            }
        }
        DomCmd::Messages { file } => {
            let body = read_or_stdin(&file)?;
            for e in find_message_endpoints(&String::from_utf8_lossy(&body)) {
                let flags = match (e.wildcard_origin, e.origin_validated) {
                    (true, _) => "wildcard-origin",
                    (false, false) => "no-origin-check",
                    (false, true) => "origin-validated",
                };
                println!("L{}: {:?} [{}]\n   {}", e.line, e.kind, flags, e.snippet);
            }
        }
        DomCmd::Gadgets { file } => {
            let body = read_or_stdin(&file)?;
            for g in find_gadgets(&String::from_utf8_lossy(&body)) {
                println!("L{}: {} ({})\n   {}", g.line, g.gadget, g.library.as_deref().unwrap_or("custom"), g.snippet);
            }
        }
        DomCmd::Clobber { file } => {
            let body = read_or_stdin(&file)?;
            for c in detect_clobbering(&String::from_utf8_lossy(&body)) {
                println!("L{}: <{}> clobbers `{}`\n   {}", c.line, c.element, c.clobbers, c.snippet);
            }
        }
    }
    Ok(())
}

fn read_or_stdin(p: &str) -> Result<Vec<u8>> {
    if p == "-" {
        let mut s = Vec::new();
        std::io::stdin().read_to_end(&mut s)?;
        Ok(s)
    } else {
        Ok(std::fs::read(PathBuf::from(p))?)
    }
}
