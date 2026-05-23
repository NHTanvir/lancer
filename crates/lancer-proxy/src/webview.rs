//! Embedded browser via `wry` (system webview: WebView2 on Windows, WebKit on
//! macOS, WebKitGTK on Linux).
//!
//! Feature-gated. The default build keeps the system-browser launcher in
//! `crate::browser`; rebuild with `--features embedded-browser` to use the
//! in-process webview for the "Open browser" feature.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebViewConfig {
    pub initial_url: String,
    pub proxy: Option<String>,
    pub user_data_dir: Option<std::path::PathBuf>,
    pub width: u32,
    pub height: u32,
    pub title: String,
}

impl Default for WebViewConfig {
    fn default() -> Self {
        Self {
            initial_url: "about:blank".into(),
            proxy: None,
            user_data_dir: None,
            width: 1200,
            height: 800,
            title: "Lancer Browser".into(),
        }
    }
}

#[cfg(feature = "embedded-browser")]
pub fn launch(cfg: WebViewConfig) -> anyhow::Result<()> {
    use tao::dpi::LogicalSize;
    use tao::event::{Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoop};
    use tao::window::WindowBuilder;
    use wry::WebViewBuilder;

    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title(&cfg.title)
        .with_inner_size(LogicalSize::new(cfg.width as f64, cfg.height as f64))
        .build(&event_loop)?;

    let mut builder = WebViewBuilder::new(&window).with_url(&cfg.initial_url);
    if let Some(p) = &cfg.proxy {
        builder = builder.with_proxy_config(wry::ProxyConfig::Http(wry::ProxyEndpoint {
            host: p.split(':').next().unwrap_or(p).to_string(),
            port: p.split(':').nth(1).unwrap_or("8080").to_string(),
        }));
    }
    let _webview = builder.build()?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent { event: WindowEvent::CloseRequested, .. } = event {
            *control_flow = ControlFlow::Exit;
        }
    });
}

#[cfg(not(feature = "embedded-browser"))]
pub fn launch(_cfg: WebViewConfig) -> anyhow::Result<()> {
    anyhow::bail!("embedded webview disabled — rebuild with `--features embedded-browser`")
}
