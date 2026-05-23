//! Android — ADB-driven CA install + proxy steering.

use std::path::Path;
use std::process::Stdio;

use anyhow::{anyhow, Context, Result};
use tokio::process::Command;

pub struct Adb {
    pub serial: Option<String>,
}

impl Adb {
    pub fn new(serial: Option<String>) -> Self {
        Self { serial }
    }

    async fn cmd(&self, args: &[&str]) -> Result<String> {
        let mut command = Command::new("adb");
        if let Some(s) = &self.serial {
            command.arg("-s").arg(s);
        }
        command.args(args);
        let out = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("adb")?;
        if !out.status.success() {
            return Err(anyhow!(
                "adb {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    pub async fn devices(&self) -> Result<Vec<String>> {
        let s = self.cmd(&["devices"]).await?;
        Ok(s.lines()
            .skip(1)
            .filter_map(|l| {
                let l = l.trim();
                if l.is_empty() {
                    None
                } else {
                    l.split_whitespace().next().map(|s| s.to_string())
                }
            })
            .collect())
    }

    /// Push a DER-encoded CA cert into the user-trust store. The device must
    /// allow user certs (most non-Network-Security-Config apps will trust
    /// them; system-trust requires root).
    pub async fn install_user_ca(&self, der_path: &Path) -> Result<()> {
        // Android user-store hash filename is the OpenSSL subject_hash_old of the cert.
        // We rely on `openssl` being on PATH for that — fall back to a fixed name.
        let hash = openssl_subject_hash_old(der_path)
            .unwrap_or_else(|| "lancerca".to_string());
        let on_device = format!("/sdcard/{hash}.0");
        self.cmd(&["push", der_path.to_str().unwrap(), &on_device]).await?;
        // Move into /data/misc/user/0/cacerts-added/ (requires su on most stock builds).
        self.cmd(&[
            "shell",
            &format!(
                "su 0 mv {on_device} /data/misc/user/0/cacerts-added/{hash}.0"
            ),
        ])
        .await
        .ok();
        Ok(())
    }

    /// Send the device through `host:port` for all HTTP/S traffic.
    pub async fn set_proxy(&self, host: &str, port: u16) -> Result<()> {
        self.cmd(&[
            "shell",
            "settings",
            "put",
            "global",
            "http_proxy",
            &format!("{host}:{port}"),
        ])
        .await
        .map(|_| ())
    }

    pub async fn clear_proxy(&self) -> Result<()> {
        self.cmd(&["shell", "settings", "put", "global", "http_proxy", ":0"])
            .await
            .map(|_| ())
    }
}

fn openssl_subject_hash_old(der_path: &Path) -> Option<String> {
    let out = std::process::Command::new("openssl")
        .args([
            "x509",
            "-inform",
            "der",
            "-in",
            der_path.to_str()?,
            "-subject_hash_old",
            "-noout",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
