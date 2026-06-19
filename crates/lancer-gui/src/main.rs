//! Lancer GUI — desktop window.
//!
//! Starts the embedded GUI HTTP server, spawns `lancer-api` as a child process
//! to serve `/v1/*`, then opens a native desktop window via wry pointing at
//! the GUI server.

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod commands_ipc;
mod static_assets;

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::{Icon, WindowBuilder};
use tracing_subscriber::EnvFilter;
use wry::WebViewBuilder;

fn main() -> Result<()> {
    lancer_proxy::install_crypto_provider();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    let gui_port = pick_free_port()?;
    let api_port = pick_free_port()?;
    let gui_addr: SocketAddr = format!("127.0.0.1:{gui_port}").parse()?;
    let api_addr = format!("127.0.0.1:{api_port}");

    // Spawn lancer-api as a child process.
    let mut api_child = spawn_api(&api_addr)?;
    // Wait briefly for it to bind.
    wait_for_listen(&api_addr, Duration::from_secs(8))?;

    // Run the embedded GUI server on a dedicated tokio runtime in a worker thread.
    let api_backend = api_addr.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(async move {
            let state = app::AppState::new(api_backend).await.expect("AppState");
            app::serve(state, gui_addr).await.expect("gui server");
        });
    });
    wait_for_listen(&format!("127.0.0.1:{gui_port}"), Duration::from_secs(8))?;

    // Open a native window with a webview pointing at the GUI server.
    let event_loop = EventLoopBuilder::new().build();
    let mut wb = WindowBuilder::new()
        .with_title("Lancer")
        .with_inner_size(tao::dpi::LogicalSize::new(1400.0, 900.0))
        .with_visible(true);
    if let Some(icon) = load_window_icon() {
        wb = wb.with_window_icon(Some(icon));
    }
    let window = wb.build(&event_loop)?;
    // Force the window to the foreground (bash launches it minimized/background).
    window.set_minimized(false);
    window.set_visible(true);
    window.set_focus();
    let _webview = WebViewBuilder::new()
        .with_url(&format!("http://127.0.0.1:{gui_port}/"))
        .build(&window)?;

    // Ensure we reap the API child when the window closes.
    let api_guard = ApiGuard(Arc::new(parking_lot::Mutex::new(Some(api_child))));
    let guard_clone = api_guard.clone();

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            guard_clone.kill();
            *control_flow = ControlFlow::Exit;
        }
    });
}

#[derive(Clone)]
struct ApiGuard(Arc<parking_lot::Mutex<Option<Child>>>);

impl ApiGuard {
    fn kill(&self) {
        if let Some(mut c) = self.0.lock().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for ApiGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

fn spawn_api(listen: &str) -> Result<Child> {
    let exe = locate_api()?;
    let mut cmd = Command::new(exe);
    cmd.arg("--listen")
        .arg(listen)
        .arg("--project")
        .arg(default_project_path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.spawn().context("spawning lancer-api")
}

fn locate_api() -> Result<PathBuf> {
    let me = std::env::current_exe().context("current_exe")?;
    let dir = me.parent().context("exe has no parent")?;
    let exe_name = if cfg!(windows) { "lancer-api.exe" } else { "lancer-api" };
    let candidate = dir.join(exe_name);
    if candidate.exists() {
        return Ok(candidate);
    }
    // Dev fallback: target/debug or target/release sibling
    let dev = dir.join(exe_name);
    if dev.exists() {
        return Ok(dev);
    }
    // Last resort: search PATH
    Ok(PathBuf::from(exe_name))
}

fn default_project_path() -> PathBuf {
    let base = dirs_data_local().unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join("Lancer");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("default.lancer")
}

fn dirs_data_local() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share"))
            })
    }
}

fn pick_free_port() -> Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0").context("bind 0")?;
    let port = l.local_addr()?.port();
    drop(l);
    Ok(port)
}

fn load_window_icon() -> Option<Icon> {
    const RGBA: &[u8] = include_bytes!("../assets/lancer-32.rgba");
    Icon::from_rgba(RGBA.to_vec(), 32, 32).ok()
}

fn wait_for_listen(addr: &str, timeout: Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(
            &addr.parse().context("parse addr")?,
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    anyhow::bail!("timed out waiting for {addr} to listen");
}
