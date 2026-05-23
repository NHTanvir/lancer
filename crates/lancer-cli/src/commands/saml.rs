//! `lancer saml` — SAML Raider.

use std::io::Read;

use anyhow::Result;
use clap::{Args, Subcommand};
use lancer_tools::saml::{decode, encode, strip_signature, xsw_wrap};

#[derive(Debug, Args)]
pub struct SamlArgs {
    #[command(subcommand)]
    cmd: SamlCmd,
}

#[derive(Debug, Subcommand)]
enum SamlCmd {
    Decode { token: String },
    Encode { xml_file: String, #[arg(long)] deflate: bool },
    StripSignature { xml_file: String },
    XswWrap { xml_file: String, malicious_assertion_file: String },
}

pub async fn run(args: SamlArgs) -> Result<()> {
    match args.cmd {
        SamlCmd::Decode { token } => {
            let token = if token == "-" {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s
            } else {
                token
            };
            let d = decode(&token)?;
            println!("{}", d.xml);
            eprintln!("(deflated={})", d.was_deflated);
        }
        SamlCmd::Encode { xml_file, deflate } => {
            let xml = std::fs::read_to_string(xml_file)?;
            println!("{}", encode(&xml, deflate)?);
        }
        SamlCmd::StripSignature { xml_file } => {
            let xml = std::fs::read_to_string(xml_file)?;
            print!("{}", strip_signature(&xml));
        }
        SamlCmd::XswWrap { xml_file, malicious_assertion_file } => {
            let xml = std::fs::read_to_string(xml_file)?;
            let m = std::fs::read_to_string(malicious_assertion_file)?;
            print!("{}", xsw_wrap(&xml, &m));
        }
    }
    Ok(())
}
