use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, ValueEnum};
use lancer_tools::comparer::{Comparer, DiffMode, DiffOp};

#[derive(Debug, Args)]
pub struct CompareArgs {
    a: PathBuf,
    b: PathBuf,
    #[arg(long, value_enum, default_value_t = Mode::Words)]
    mode: Mode,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Mode {
    Bytes,
    Words,
}

pub async fn run(args: CompareArgs) -> Result<()> {
    let a = std::fs::read_to_string(&args.a)?;
    let b = std::fs::read_to_string(&args.b)?;
    let mode = match args.mode {
        Mode::Bytes => DiffMode::Bytes,
        Mode::Words => DiffMode::Words,
    };
    for op in Comparer::diff(&a, &b, mode) {
        match op {
            DiffOp::Equal(s) => print!("{s} "),
            DiffOp::Delete(s) => print!("\x1b[31m-{s}\x1b[0m "),
            DiffOp::Insert(s) => print!("\x1b[32m+{s}\x1b[0m "),
        }
    }
    println!();
    Ok(())
}
