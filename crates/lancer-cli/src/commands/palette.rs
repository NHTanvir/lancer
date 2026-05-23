//! `lancer palette` — search the command palette from the CLI.

use anyhow::Result;
use clap::Args;
use lancer_plugin::CommandPalette;

#[derive(Debug, Args)]
pub struct PaletteArgs {
    query: Option<String>,
}

pub async fn run(args: PaletteArgs) -> Result<()> {
    let palette = CommandPalette::new();
    let results = palette.search(args.query.as_deref().unwrap_or(""));
    for c in results {
        let hot = c.hotkey.as_deref().unwrap_or("");
        println!("{:32} {:30} {hot}", c.id, c.label);
    }
    Ok(())
}
