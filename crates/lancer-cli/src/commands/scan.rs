//! `lancer scan` — run passive/active checks against a target.

use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use lancer_core::HttpRequest;
use lancer_scanner::config::{ScanConfig, ScanPreset};
use lancer_scanner::ScanEngine;
use lancer_storage::Storage;
use lancer_tools::HttpClient;

#[derive(Debug, Args)]
pub struct ScanArgs {
    #[command(subcommand)]
    cmd: ScanCmd,
}

#[derive(Debug, Subcommand)]
enum ScanCmd {
    /// Run passive checks against an arbitrary URL (fetches it first).
    Passive {
        url: String,
        #[arg(long)]
        project: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Preset::Balanced)]
        preset: Preset,
    },
    /// Run active checks against a request template (file or `-`).
    Active {
        request: String,
        #[arg(long, default_value = "https")]
        scheme: String,
        #[arg(long)]
        project: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Preset::Balanced)]
        preset: Preset,
    },
    /// Run both passive and active checks against a URL.
    Full {
        url: String,
        #[arg(long)]
        project: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Preset::Balanced)]
        preset: Preset,
    },
    /// Show all available check IDs.
    ListChecks,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Preset {
    Lightweight,
    Balanced,
    Deep,
    AuditOnly,
    CrawlOnly,
    PassiveOnly,
    OwaspTop10,
}

impl From<Preset> for ScanPreset {
    fn from(p: Preset) -> Self {
        match p {
            Preset::Lightweight => ScanPreset::Lightweight,
            Preset::Balanced => ScanPreset::Balanced,
            Preset::Deep => ScanPreset::Deep,
            Preset::AuditOnly => ScanPreset::AuditOnly,
            Preset::CrawlOnly => ScanPreset::CrawlOnly,
            Preset::PassiveOnly => ScanPreset::PassiveOnly,
            Preset::OwaspTop10 => ScanPreset::OwaspTop10,
        }
    }
}

pub async fn run(args: ScanArgs) -> Result<()> {
    match args.cmd {
        ScanCmd::ListChecks => {
            println!("passive:");
            for c in lancer_scanner::passive::registry() {
                println!("  {}\t{}", c.id(), c.name());
            }
            println!("active:");
            for c in lancer_scanner::active::registry() {
                println!("  {}\t{}", c.id(), c.name());
            }
        }
        ScanCmd::Passive { url, project, preset } => {
            let engine = build_engine(preset, project).await?;
            let req = HttpRequest::builder("GET", &url)?;
            let resp = engine.client.send(&req).await?;
            let issues = engine.run_passive(&req, &resp).await;
            print_issues(&issues);
        }
        ScanCmd::Active { request, scheme, project, preset } => {
            let raw = read_or_stdin(&request)?;
            let mut req = HttpRequest::parse_wire(&raw)?;
            req.meta.scheme = scheme;
            if req.meta.scheme == "https" && req.meta.port == 80 {
                req.meta.port = 443;
            }
            let engine = build_engine(preset, project).await?;
            let issues = engine.run_active(&req).await?;
            print_issues(&issues);
        }
        ScanCmd::Full { url, project, preset } => {
            let engine = build_engine(preset, project).await?;
            let req = HttpRequest::builder("GET", &url)?;
            let resp = engine.client.send(&req).await?;
            let mut issues = engine.run_passive(&req, &resp).await;
            issues.extend(engine.run_active(&req).await?);
            print_issues(&issues);
        }
    }
    Ok(())
}

async fn build_engine(preset: Preset, project: Option<PathBuf>) -> Result<ScanEngine> {
    let mut config = ScanConfig::default();
    config.preset = preset.into();
    let issue_store = if let Some(p) = project {
        Some(Storage::open(p).await?.issues())
    } else {
        None
    };
    Ok(ScanEngine::new(config, HttpClient::new(), issue_store))
}

fn print_issues(issues: &[lancer_storage::issues::Issue]) {
    if issues.is_empty() {
        println!("no findings");
        return;
    }
    for i in issues {
        println!(
            "[{}/{}] {} — {}",
            i.severity.as_str(),
            i.confidence.as_str(),
            i.name,
            i.description
        );
        if let Some(r) = &i.remediation {
            println!("  remediation: {r}");
        }
    }
}

fn read_or_stdin(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        Ok(std::fs::read(path)?)
    }
}
