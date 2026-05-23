use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use lancer_proxy::ca::{CaConfig, CertificateAuthority};

#[derive(Debug, Args)]
pub struct CertArgs {
    #[command(subcommand)]
    cmd: CertCmd,
}

#[derive(Debug, Subcommand)]
enum CertCmd {
    /// Generate the CA if not present.
    Init {
        #[arg(long, default_value = "./ca")]
        dir: PathBuf,
    },
    /// Export the CA in DER format.
    ExportDer {
        #[arg(long, default_value = "./ca")]
        dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Export the CA in PEM format.
    ExportPem {
        #[arg(long, default_value = "./ca")]
        dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}

pub async fn run(args: CertArgs) -> Result<()> {
    match args.cmd {
        CertCmd::Init { dir } => {
            let cfg = CaConfig { dir, ..Default::default() };
            let _ca = CertificateAuthority::load_or_create(cfg)?;
            println!("CA ready.");
        }
        CertCmd::ExportDer { dir, out } => {
            let ca = CertificateAuthority::load_or_create(CaConfig { dir, ..Default::default() })?;
            ca.write_der(&out)?;
            println!("DER written to {}", out.display());
        }
        CertCmd::ExportPem { dir, out } => {
            let ca = CertificateAuthority::load_or_create(CaConfig { dir, ..Default::default() })?;
            ca.write_pem(&out)?;
            println!("PEM written to {}", out.display());
        }
    }
    Ok(())
}
