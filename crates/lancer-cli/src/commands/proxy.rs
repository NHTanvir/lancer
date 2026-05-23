use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Args;
use lancer_core::scope::Scope;
use lancer_proxy::ca::{CaConfig, CertificateAuthority};
use lancer_proxy::events::ProxyEventSink;
use lancer_proxy::intercept::InterceptEngine;
use lancer_proxy::listener::ProxyListener;
use lancer_proxy::match_replace::MatchReplaceEngine;
use lancer_proxy::settings::{ListenerBind, ProxySettings};
use lancer_storage::Storage;
use parking_lot::RwLock;
use tracing::info;

#[derive(Debug, Args)]
pub struct ProxyArgs {
    /// `host:port` to bind. May be passed multiple times.
    #[arg(long, default_values_t = vec!["127.0.0.1:8080".to_string()])]
    listen: Vec<String>,

    /// Where to store / read the CA.
    #[arg(long, default_value = "./ca")]
    ca_dir: PathBuf,

    /// Project file (`.lancer`). If omitted, traffic is captured in memory.
    #[arg(long)]
    project: Option<PathBuf>,

    /// Pass-through hostnames (no MITM).
    #[arg(long)]
    passthrough: Vec<String>,
}

pub async fn run(args: ProxyArgs) -> Result<()> {
    let mut settings = ProxySettings::default();
    settings.listeners.clear();
    for s in &args.listen {
        let addr = s.parse()?;
        settings.listeners.push(ListenerBind { addr, transparent: false });
    }
    settings.ca_dir = args.ca_dir.clone();
    settings.tls_passthrough = args.passthrough.clone();
    let settings = Arc::new(settings);

    let ca = Arc::new(CertificateAuthority::load_or_create(CaConfig {
        dir: args.ca_dir,
        ..Default::default()
    })?);

    let storage = match args.project {
        Some(path) => Some(Storage::open(path).await?),
        None => None,
    };

    let history = storage.as_ref().map(|s| s.history());
    let (event_sink, mut event_rx) = ProxyEventSink::new(1024);
    let scope = Arc::new(RwLock::new(Scope::new()));
    let intercept = InterceptEngine::default();
    let match_replace = MatchReplaceEngine::default();

    // background drain so the sink never fills (real GUI/subscribers will replace this)
    tokio::spawn(async move {
        while let Some(ev) = event_rx.recv().await {
            tracing::trace!(?ev, "proxy event");
        }
    });

    let listener = Arc::new(ProxyListener::new(
        settings.clone(),
        ca,
        intercept,
        match_replace,
        scope,
        history,
        event_sink,
    ));
    info!("starting Lancer proxy");
    listener.run().await
}
