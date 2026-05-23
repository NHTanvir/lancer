use std::io::{Read, Write};

use anyhow::Result;
use clap::Args;
use lancer_core::transform::{chain, smart_decode, TransformOp};

#[derive(Debug, Args)]
pub struct DecodeArgs {
    /// Ordered ops, e.g. `--op base64-decode --op gzip-decode`.
    #[arg(long = "op")]
    ops: Vec<String>,
    /// Run the smart-decode auto-detection loop instead of explicit ops.
    #[arg(long)]
    smart: bool,
}

pub async fn run(args: DecodeArgs) -> Result<()> {
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf)?;
    let out = if args.smart {
        smart_decode(&buf)
    } else {
        let ops: Vec<TransformOp> = args
            .ops
            .iter()
            .filter_map(|s| TransformOp::parse(s))
            .collect();
        chain(&ops, &buf)?
    };
    std::io::stdout().write_all(&out)?;
    Ok(())
}
