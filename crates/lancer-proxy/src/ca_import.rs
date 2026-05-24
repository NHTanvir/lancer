//! Import an externally supplied CA (cert + key) and use it instead of the
//! self-generated one. Useful when the user already has a private CA they
//! trust across machines.

use std::path::Path;

use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair};

use crate::ca::{CaConfig, CertificateAuthority};

pub fn import_from_pem(
    cert_pem_path: &Path,
    key_pem_path: &Path,
    config: CaConfig,
) -> Result<CertificateAuthority> {
    std::fs::create_dir_all(&config.dir).context("creating CA dir")?;
    let cert_pem = std::fs::read_to_string(cert_pem_path).context("reading cert pem")?;
    let key_pem = std::fs::read_to_string(key_pem_path).context("reading key pem")?;
    let kp = KeyPair::from_pem(&key_pem).context("parsing imported key")?;
    let params = CertificateParams::from_ca_cert_pem(&cert_pem)
        .context("parsing imported CA certificate")?;
    let _cert = params
        .self_signed(&kp)
        .context("imported cert + key don't pair")?;
    std::fs::write(config.dir.join("ca.pem"), &cert_pem)?;
    std::fs::write(config.dir.join("ca.key"), &key_pem)?;
    CertificateAuthority::load_or_create(config)
}
