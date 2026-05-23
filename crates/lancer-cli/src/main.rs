//! Lancer CLI entrypoint.

mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "lancer",
    about = "Web-application security testing suite",
    version
)]
struct Cli {
    /// Logging filter (e.g. info, debug, lancer_proxy=debug)
    #[arg(long, env = "LANCER_LOG", default_value = "info")]
    log: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// CA-certificate management.
    Cert(commands::cert::CertArgs),
    /// Start the intercepting proxy.
    Proxy(commands::proxy::ProxyArgs),
    /// Project file utilities.
    Project(commands::project::ProjectArgs),
    /// Browse stored HTTP history.
    History(commands::history::HistoryArgs),
    /// Decode/encode/hash transforms (stdin → stdout).
    Decode(commands::decode::DecodeArgs),
    /// Quick word/byte diff between two files.
    Compare(commands::compare::CompareArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(&cli.log).unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        match cli.cmd {
            Cmd::Cert(a) => commands::cert::run(a).await,
            Cmd::Proxy(a) => commands::proxy::run(a).await,
            Cmd::Project(a) => commands::project::run(a).await,
            Cmd::History(a) => commands::history::run(a).await,
            Cmd::Decode(a) => commands::decode::run(a).await,
            Cmd::Compare(a) => commands::compare::run(a).await,
        }
    })
}
