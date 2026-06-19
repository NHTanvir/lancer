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
    /// §40 Deserialization payload generator (ysoserial-equivalent).
    Ysoserial(commands::ysoserial::YsoserialArgs),
    /// §42 LLM vulnerability scanner (garak-equivalent).
    #[command(name = "llm-scan")]
    LlmScan(commands::llm_scan::LlmScanArgs),
    /// §43 LLM red-team orchestrator (PyRIT-equivalent).
    #[command(name = "llm-redteam")]
    LlmRedteam(commands::llm_redteam::LlmRedteamArgs),
    /// §44 MCP server scanner (mcp-scan-equivalent).
    #[command(name = "mcp-scan")]
    McpScan(commands::mcp_scan::McpScanArgs),
    /// §47 AI Repeater variant generator (Shadow Repeater).
    Shadow(commands::shadow::ShadowArgs),
    /// §48 Stateful API fuzzer (RESTler-equivalent).
    #[command(name = "stateful-fuzz")]
    StatefulFuzz(commands::stateful_fuzz::StatefulFuzzArgs),
    /// §50 CMS-aware scanner (WPScan / JoomScan / Droopescan-equivalent).
    #[command(name = "cms-scan")]
    CmsScan(commands::cms_scan::CmsScanArgs),
    /// §51 Exploit-DB lookup (searchsploit-equivalent).
    Exploits(commands::exploits::ExploitsArgs),
    /// §45 Shodan host enrichment.
    Shodan(commands::shodan::ShodanArgs),
    /// §52 Modules system (list / enable / disable / status / preset).
    Modules(commands::modules::ModulesArgs),
    /// §4.6 High-speed content/parameter fuzzer (ffuf-equivalent).
    Fuzz(commands::fuzz::FuzzArgs),
    /// §25 Throughput benchmark (req/s + latency percentiles).
    Bench(commands::bench::BenchArgs),
    /// §58 MCP server — expose Lancer to AI agents over stdio (Model Context Protocol).
    Mcp(commands::mcp::McpArgs),
    /// §57 Infiltrator — emit a Frida sink-taint-tracking script for the target runtime.
    Infiltrator(commands::infiltrator::InfiltratorArgs),
}

fn main() -> Result<()> {
    lancer_proxy::install_crypto_provider();
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
            Cmd::Ysoserial(a) => commands::ysoserial::run(a),
            Cmd::LlmScan(a) => commands::llm_scan::run(a).await,
            Cmd::LlmRedteam(a) => commands::llm_redteam::run(a).await,
            Cmd::McpScan(a) => commands::mcp_scan::run(a).await,
            Cmd::Shadow(a) => commands::shadow::run(a),
            Cmd::StatefulFuzz(a) => commands::stateful_fuzz::run(a).await,
            Cmd::CmsScan(a) => commands::cms_scan::run(a).await,
            Cmd::Exploits(a) => commands::exploits::run(a),
            Cmd::Shodan(a) => commands::shodan::run(a).await,
            Cmd::Modules(a) => commands::modules::run(a).await,
            Cmd::Fuzz(a) => commands::fuzz::run_cmd(a).await,
            Cmd::Bench(a) => commands::bench::run(a).await,
            Cmd::Mcp(a) => commands::mcp::run(a).await,
            Cmd::Infiltrator(a) => commands::infiltrator::run(a).await,
        }
    })
}
