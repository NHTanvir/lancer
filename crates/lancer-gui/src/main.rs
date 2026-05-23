//! Lancer GUI shell.
//!
//! This binary intentionally builds without Tauri unless `--features tauri`
//! is set; without that feature it serves a local HTTP API and prints the URL,
//! so the React/Svelte frontend can be developed against it without webkit
//! installed. The real Tauri integration is wired in once Tauri 2.x is ready
//! on the build host.

mod app;
mod commands_ipc;
mod static_assets;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    let app = app::AppState::new().await?;
    #[cfg(feature = "tauri")]
    {
        // tauri::Builder::default()
        //     .manage(app)
        //     .invoke_handler(tauri::generate_handler![
        //         commands_ipc::proxy_status,
        //         commands_ipc::history_list,
        //         commands_ipc::history_show,
        //         commands_ipc::scan_full,
        //         commands_ipc::repeater_send,
        //         commands_ipc::report_render,
        //     ])
        //     .run(tauri::generate_context!())?;
        // Tauri is only enabled when its system deps are present.
        eprintln!("tauri feature is enabled; wire `tauri::Builder` here.");
        std::future::pending::<()>().await;
    }
    #[cfg(not(feature = "tauri"))]
    {
        app::run_dev_server(app).await?;
    }
    Ok(())
}
