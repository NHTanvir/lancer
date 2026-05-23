//! `lancer convert` — JSON ↔ XML body converter.

use std::io::Read;

use anyhow::Result;
use clap::{Args, Subcommand};
use lancer_tools::content_convert::{json_to_xml, xml_to_json};

#[derive(Debug, Args)]
pub struct ConvertArgs {
    #[command(subcommand)]
    cmd: ConvertCmd,
}

#[derive(Debug, Subcommand)]
enum ConvertCmd {
    JsonToXml { file: String, #[arg(long, default_value = "root")] root: String },
    XmlToJson { file: String },
}

pub async fn run(args: ConvertArgs) -> Result<()> {
    let read = |p: &str| -> Result<String> {
        if p == "-" {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            Ok(s)
        } else {
            Ok(std::fs::read_to_string(p)?)
        }
    };
    match args.cmd {
        ConvertCmd::JsonToXml { file, root } => print!("{}", json_to_xml(&read(&file)?, &root)?),
        ConvertCmd::XmlToJson { file } => print!("{}", xml_to_json(&read(&file)?)?),
    }
    Ok(())
}
