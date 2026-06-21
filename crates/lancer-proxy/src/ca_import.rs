//! Import an externally supplied CA (cert + key) and use it instead of the
//! self-generated one. Useful when the user already has a private CA they
//! trust across machines.

use std::path::Path;

use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair};
use x509_parser::prelude::*;

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

    // Actually verify the imported cert and key pair: compare the certificate's
    // SubjectPublicKeyInfo DER against the keypair's public key DER. (self_signed
    // would mint a brand-new cert from any valid key and never compares them.)
    let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .ok_or_else(|| anyhow::anyhow!("imported CA pem has no certificate"))??;
    let (_, parsed) = X509Certificate::from_der(der.as_ref())
        .context("parsing imported CA certificate DER")?;
    let cert_spki = parsed.public_key().raw; // full SubjectPublicKeyInfo DER
    let key_spki = kp.public_key_der(); // rcgen KeyPair SPKI DER
    if cert_spki != key_spki.as_slice() {
        anyhow::bail!("imported certificate and private key do not match");
    }

    // Parse params for validation; the pairing is now enforced above.
    let _params = CertificateParams::from_ca_cert_pem(&cert_pem)
        .context("parsing imported CA certificate")?;
    std::fs::write(config.dir.join("ca.pem"), &cert_pem)?;
    std::fs::write(config.dir.join("ca.key"), &key_pem)?;
    CertificateAuthority::load_or_create(config)
}
