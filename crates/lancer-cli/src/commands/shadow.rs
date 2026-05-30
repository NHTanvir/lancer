//! `lancer shadow` — §47 AI Repeater Variants.
//!
//! One-shot mutation-variant generation from a raw HTTP request. Reads the
//! request from a file path (positional `<request.http>`) or from stdin when
//! the path is `-` (or omitted). Mirrors the `/v1/shadow/generate` handler:
//! builds a `ShadowRequest` and calls `lancer_shadow::generate_variants`.
//!
//!   lancer shadow request.http
//!   cat request.http | lancer shadow -
//!   lancer shadow request.http --family injection --family idor --max 8 --json

use std::io::Read;

use anyhow::Result;
use clap::{Args, ValueEnum};
use lancer_shadow::{generate_variants, MutationFamily, ShadowRequest, ShadowVariant};

#[derive(Debug, Args)]
pub struct ShadowArgs {
    /// Path to a raw HTTP request file, or `-` for stdin (default: stdin).
    #[arg(default_value = "-")]
    request: String,

    /// Mutation families to apply. Repeatable; defaults to all families.
    #[arg(long, value_enum)]
    family: Vec<Family>,

    /// Maximum number of variants to generate.
    #[arg(long, default_value_t = 5)]
    max: usize,

    /// Emit the variants as pretty JSON instead of human-readable text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Family {
    AuthBypass,
    Idor,
    Injection,
    Encoding,
    ParameterPollution,
    PathTraversal,
}

impl From<Family> for MutationFamily {
    fn from(f: Family) -> Self {
        match f {
            Family::AuthBypass => MutationFamily::AuthBypass,
            Family::Idor => MutationFamily::Idor,
            Family::Injection => MutationFamily::Injection,
            Family::Encoding => MutationFamily::Encoding,
            Family::ParameterPollution => MutationFamily::ParameterPollution,
            Family::PathTraversal => MutationFamily::PathTraversal,
        }
    }
}

fn all_families() -> Vec<MutationFamily> {
    vec![
        MutationFamily::AuthBypass,
        MutationFamily::Idor,
        MutationFamily::Injection,
        MutationFamily::Encoding,
        MutationFamily::ParameterPollution,
        MutationFamily::PathTraversal,
    ]
}

pub fn run(args: ShadowArgs) -> Result<()> {
    let raw_request = read_or_stdin(&args.request)?;

    let families: Vec<MutationFamily> = if args.family.is_empty() {
        all_families()
    } else {
        args.family.into_iter().map(MutationFamily::from).collect()
    };

    let req = ShadowRequest {
        raw_request,
        families,
        max_variants: args.max,
    };

    let variants = generate_variants(&req);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&variants)?);
    } else {
        print_variants(&variants);
    }

    Ok(())
}

fn print_variants(variants: &[ShadowVariant]) {
    if variants.is_empty() {
        println!("no variants generated");
        return;
    }
    println!("generated {} variant(s):", variants.len());
    for v in variants {
        println!();
        println!("── {:?} — {}", v.family, v.description);
        println!("   id: {}  score: {:.2}", v.id, v.score);
        println!("{}", v.raw_request);
    }
}

fn read_or_stdin(path: &str) -> Result<String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        Ok(std::fs::read_to_string(path)?)
    }
}
