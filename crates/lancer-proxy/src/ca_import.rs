//! Import an externally supplied CA (cert + key) and use it instead of the
//! self-generated one. Useful when the user already has a private CA they
//! trust across machines.

use std::path::Path;

use anyhow::{Context, Result};
use rcgen::{Issuer, KeyPair};

use crate::ca::{CaConfig, CertificateAuthority};

/// Import a CA from arbitrary PEM paths into the configured `ca_dir`.
/// Writes them as `ca.pem` / `ca.key` so the rest of the proxy picks them up
/// on next start.
pub fn import_from_pem(
    cert_pem_path: &Path,
    key_pem_path: &Path,
    config: CaConfig,
) -> Result<CertificateAuthority> {
    std::fs::create_dir_all(&config.dir).context("creating CA dir")?;
    let cert_pem = std::fs::read_to_string(cert_pem_path).context("reading cert pem")?;
    let key_pem = std::fs::read_to_string(key_pem_path).context("reading key pem")?;
    // sanity-check the keypair parses + signs the cert
    let _kp = KeyPair::from_pem(&key_pem).context("parsing imported key")?;
    let _issuer = Issuer::from_ca_cert_pem(
        &cert_pem,
        KeyPair::from_pem(&key_pem)?,
    )
    .context("imported cert + key don't pair")?;
    std::fs::write(config.dir.join("ca.pem"), &cert_pem)?;
    std::fs::write(config.dir.join("ca.key"), &key_pem)?;
    CertificateAuthority::load_or_create(config)
}
