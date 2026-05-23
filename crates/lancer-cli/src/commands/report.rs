//! `lancer report` — render scanner findings in the chosen format.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, ValueEnum};
use lancer_report::{
    render_html, render_json, render_markdown, render_sarif, render_xml, ReportFilter, ReportMeta,
};
use lancer_storage::Storage;

#[derive(Debug, Args)]
pub struct ReportArgs {
    #[arg(long)]
    project: PathBuf,
    #[arg(long, value_enum, default_value_t = Format::Html)]
    format: Format,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long, default_value = "Lancer project")]
    project_name: String,
    #[arg(long)]
    title: Option<String>,
    #[arg(long)]
    executive_summary: Option<String>,
    #[arg(long)]
    min_severity: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Html,
    Json,
    Markdown,
    Sarif,
    Xml,
}

pub async fn run(args: ReportArgs) -> Result<()> {
    let storage = Storage::open(&args.project).await?;
    let issues = storage.issues().list().await?;
    let mut meta = ReportMeta::new(args.project_name);
    if let Some(t) = args.title {
        meta.title = t;
    }
    meta.executive_summary = args.executive_summary;
    let mut filter = ReportFilter::default();
    if let Some(s) = args.min_severity {
        filter.min_severity = lancer_storage::issues::Severity::parse(&s);
    }
    let body = match args.format {
        Format::Html => render_html(&meta, &issues, &filter),
        Format::Json => render_json(&meta, &issues, &filter),
        Format::Markdown => render_markdown(&meta, &issues, &filter),
        Format::Sarif => render_sarif(&meta, &issues, &filter),
        Format::Xml => render_xml(&meta, &issues, &filter),
    };
    match args.out {
        Some(path) => {
            std::fs::write(&path, body)?;
            println!("wrote {}", path.display());
        }
        None => println!("{body}"),
    }
    Ok(())
}
