//! `lancer report` — render scanner findings in the chosen format.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, ValueEnum};
use lancer_report::{
    render_html, render_json, render_markdown, render_pdf, render_sarif, render_tera, render_xml,
    templates::{developer_detail, executive_summary},
    ReportFilter, ReportMeta, DEFAULT_TERA_TEMPLATE,
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
    /// Path to a custom Tera template (used with --format tera).
    #[arg(long)]
    template: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Html,
    Json,
    Markdown,
    Sarif,
    Xml,
    Pdf,
    Tera,
    ExecSummary,
    DevDetail,
}

pub async fn run(args: ReportArgs) -> Result<()> {
    let storage = Storage::open(&args.project).await?;
    let issues = storage.issues().list().await?;
    let mut meta = ReportMeta::new(args.project_name);
    if let Some(t) = args.title {
        meta.title = t;
    }
    meta.executive_summary = args.executive_summary.clone();
    let mut filter = ReportFilter::default();
    if let Some(s) = args.min_severity {
        filter.min_severity = lancer_storage::issues::Severity::parse(&s);
    }
    let body_bytes: Vec<u8> = match args.format {
        Format::Html => render_html(&meta, &issues, &filter).into_bytes(),
        Format::Json => render_json(&meta, &issues, &filter).into_bytes(),
        Format::Markdown => render_markdown(&meta, &issues, &filter).into_bytes(),
        Format::Sarif => render_sarif(&meta, &issues, &filter).into_bytes(),
        Format::Xml => render_xml(&meta, &issues, &filter).into_bytes(),
        Format::Pdf => render_pdf(&meta, &issues, &filter),
        Format::Tera => {
            let tpl = match args.template {
                Some(p) => std::fs::read_to_string(p)?,
                None => DEFAULT_TERA_TEMPLATE.to_string(),
            };
            render_tera(&tpl, &meta, &issues)?.into_bytes()
        }
        Format::ExecSummary => executive_summary(&meta, &issues).into_bytes(),
        Format::DevDetail => developer_detail(&meta, &issues).into_bytes(),
    };
    match args.out {
        Some(path) => {
            std::fs::write(&path, &body_bytes)?;
            println!("wrote {}", path.display());
        }
        None => {
            std::io::Write::write_all(&mut std::io::stdout(), &body_bytes)?;
            println!();
        }
    }
    Ok(())
}
