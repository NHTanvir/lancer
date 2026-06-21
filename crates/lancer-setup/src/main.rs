//! Lancer self-extracting installer.
//! The payload ZIP is embedded at compile-time by build.rs.

use std::fs;
use std::io::{Cursor, Read, Write as _};
use std::path::PathBuf;
use std::process::Command;

const PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/lancer-payload.zip"));

fn main() {
    // Extract to a temp directory
    let tmp = extract_payload().unwrap_or_else(|e| fatal(&format!("Extraction failed: {e}")));

    // Run install.ps1 from the temp dir
    let script = tmp.join("install.ps1");
    if !script.exists() {
        fatal("install.ps1 not found in installer payload");
    }

    let status = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", script.to_str().unwrap(),
        ])
        .status();

    // Clean up regardless of outcome
    let _ = fs::remove_dir_all(&tmp);

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("install.ps1 exited with code {:?}", s.code()),
        Err(e) => eprintln!("Failed to run install.ps1: {e}"),
    }
}

fn extract_payload() -> Result<PathBuf, Box<dyn std::error::Error>> {
    // Create a unique temp directory: %TEMP%\lancer-setup-XXXX
    let base = std::env::temp_dir();
    let uid = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let tmp = base.join(format!("lancer-setup-{uid}"));
    fs::create_dir_all(&tmp)?;

    let cursor = Cursor::new(PAYLOAD);
    let mut archive = zip::ZipArchive::new(cursor)?;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        // Reject entries with ".." / absolute paths that would escape tmp (Zip Slip).
        let safe = match file.enclosed_name() {
            Some(p) => p,
            None => continue,
        };
        let out = tmp.join(&safe);
        // Belt-and-suspenders containment check.
        if !out.starts_with(&tmp) {
            continue;
        }
        if file.is_dir() {
            fs::create_dir_all(&out)?;
        } else {
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut buf = Vec::with_capacity(file.size() as usize);
            file.read_to_end(&mut buf)?;
            fs::File::create(&out)?.write_all(&buf)?;
        }
    }
    Ok(tmp)
}

fn fatal(msg: &str) -> ! {
    eprintln!("ERROR: {msg}");
    // Keep window open so the user can read the error
    eprintln!("Press Enter to exit...");
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    std::process::exit(1);
}
