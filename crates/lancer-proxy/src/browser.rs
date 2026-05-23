//! Launch the system default browser with a clean profile and Lancer's proxy
//! configured. This is the "Open browser" button from plan.md §13. Full
//! embedded-Chromium ships later; this gets users productive immediately.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{anyhow, Result};

pub struct BrowserSession {
    pub program: String,
    pub args: Vec<String>,
    pub profile_dir: PathBuf,
    pub proxy_url: String,
}

impl BrowserSession {
    pub fn chrome(proxy: &str, profile: PathBuf) -> Self {
        Self {
            program: pick("chrome").unwrap_or_else(|| "google-chrome".into()),
            args: vec![
                format!("--proxy-server={proxy}"),
                format!("--user-data-dir={}", profile.display()),
                "--no-first-run".into(),
                "--no-default-browser-check".into(),
                "--disable-features=DownloadBubble".into(),
                "--ignore-certificate-errors-spki-list=".into(),
            ],
            profile_dir: profile,
            proxy_url: proxy.to_string(),
        }
    }

    pub fn firefox(proxy: &str, profile: PathBuf) -> Self {
        Self {
            program: pick("firefox").unwrap_or_else(|| "firefox".into()),
            args: vec![
                "-no-remote".into(),
                "-profile".into(),
                profile.display().to_string(),
                "-new-instance".into(),
                format!("--marionette-port=0"),
                "-purgecaches".into(),
                "--".into(),
                format!("http://lancer-start?proxy={proxy}"),
            ],
            profile_dir: profile,
            proxy_url: proxy.to_string(),
        }
    }

    pub fn launch(&self) -> Result<u32> {
        std::fs::create_dir_all(&self.profile_dir).ok();
        let child = Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| anyhow!("could not launch {}: {e}", self.program))?;
        Ok(child.id())
    }
}

fn pick(name: &str) -> Option<String> {
    let candidates: &[&[&str]] = match name {
        "chrome" => &[
            &["google-chrome"],
            &["chromium"],
            &["chromium-browser"],
            &["chrome"],
            &[r"C:\Program Files\Google\Chrome\Application\chrome.exe"],
            &[r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"],
        ],
        "firefox" => &[
            &["firefox"],
            &[r"C:\Program Files\Mozilla Firefox\firefox.exe"],
            &[r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"],
        ],
        _ => return None,
    };
    for cand in candidates {
        let path = cand[0];
        if std::path::Path::new(path).is_file() {
            return Some(path.to_string());
        }
        if which::which(path).is_ok() {
            return Some(path.to_string());
        }
    }
    None
}

mod which {
    use std::path::PathBuf;

    pub fn which(name: &str) -> Result<PathBuf, ()> {
        let path = std::env::var("PATH").map_err(|_| ())?;
        let sep = if cfg!(windows) { ';' } else { ':' };
        for dir in path.split(sep) {
            let candidate = std::path::Path::new(dir).join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
            if cfg!(windows) {
                let exe = std::path::Path::new(dir).join(format!("{name}.exe"));
                if exe.is_file() {
                    return Ok(exe);
                }
            }
        }
        Err(())
    }
}
