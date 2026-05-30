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
    /// Send a single request (Repeater).
    Repeater(commands::repeater::RepeaterArgs),
    /// Run an Intruder attack from a request template + payload sets.
    Intruder(commands::intruder::IntruderArgs),
    /// Analyze token randomness (Sequencer).
    Sequencer(commands::sequencer::SequencerArgs),
    /// Engagement tools (find comments/scripts/anchors, CSRF PoC, content discovery, target analyzer).
    Engagement(commands::engagement::EngagementArgs),
    /// Saved-request library (Organizer).
    Organizer(commands::organizer::OrganizerArgs),
    /// Passive + active scanner.
    Scan(commands::scan::ScanArgs),
    /// Render a scanner report (HTML / JSON / Markdown / SARIF / XML).
    Report(commands::report::ReportArgs),
    /// Search the command palette.
    Palette(commands::palette::PaletteArgs),
    /// Plugin management.
    Plugin(commands::plugin::PluginArgs),
    /// Send a prompt to the configured BYO-LLM provider.
    Ai(commands::ai::AiArgs),
    /// BFS crawler starting from a URL.
    Crawl(commands::crawl::CrawlArgs),
    /// Import an OpenAPI 3.x spec or Postman 2.1 collection.
    Import(commands::import::ImportArgs),
    /// BCheck DSL (list/lint/run).
    Bcheck(commands::bcheck::BCheckArgs),
    /// WAF fingerprinting against a URL.
    Waf(commands::waf::WafArgs),
    /// Built-in payload encyclopedia (list/search).
    Payloads(commands::payloads::PayloadsArgs),
    /// Export findings as Jira / Linear / GitHub / DefectDojo payloads.
    Export(commands::export::ExportArgs),
    /// DOM-XSS / postMessage / proto-gadget / clobbering static analysis.
    Dom(commands::dom::DomArgs),
    /// Mobile testing assistants (Android ADB, iOS profile, Frida snippets).
    Mobile(commands::mobile::MobileArgs),
    /// Parse IaC files (Dockerfile / compose / k8s / Terraform) for attack surface.
    Iac(commands::iac::IacArgs),
    /// Param Miner / Autorize / AuthMatrix.
    Miner(commands::miner::MinerArgs),
    /// SAML Raider (decode / encode / strip-signature / XSW).
    Saml(commands::saml::SamlArgs),
    /// JSON ↔ XML body converter.
    Convert(commands::convert::ConvertArgs),
    /// §49 URL pipeline toolkit — qsreplace / gf / anew / uro / unfurl.
    #[command(subcommand)]
    Url(commands::urls::UrlsCmd),
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
            Cmd::Repeater(a) => commands::repeater::run(a).await,
            Cmd::Intruder(a) => commands::intruder::run(a).await,
            Cmd::Sequencer(a) => commands::sequencer::run(a).await,
            Cmd::Engagement(a) => commands::engagement::run(a).await,
            Cmd::Organizer(a) => commands::organizer::run(a).await,
            Cmd::Scan(a) => commands::scan::run(a).await,
            Cmd::Report(a) => commands::report::run(a).await,
            Cmd::Palette(a) => commands::palette::run(a).await,
            Cmd::Plugin(a) => commands::plugin::run(a).await,
            Cmd::Ai(a) => commands::ai::run(a).await,
            Cmd::Crawl(a) => commands::crawl::run(a).await,
            Cmd::Import(a) => commands::import::run(a).await,
            Cmd::Bcheck(a) => commands::bcheck::run(a).await,
            Cmd::Waf(a) => commands::waf::run(a).await,
            Cmd::Payloads(a) => commands::payloads::run(a).await,
            Cmd::Export(a) => commands::export::run(a).await,
            Cmd::Dom(a) => commands::dom::run(a).await,
            Cmd::Mobile(a) => commands::mobile::run(a).await,
            Cmd::Iac(a) => commands::iac::run(a).await,
            Cmd::Miner(a) => commands::miner::run(a).await,
            Cmd::Saml(a) => commands::saml::run(a).await,
            Cmd::Convert(a) => commands::convert::run(a).await,
            Cmd::Url(a) => commands::urls::run(a),
        }
    })
}
