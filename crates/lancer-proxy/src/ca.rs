//! Certificate authority management.
//!
//! On first run, Lancer generates a self-signed root CA, stores it on disk, and
//! uses it to mint per-host leaf certificates on demand. The CA is the only
//! thing the user has to import into their browser/system trust store.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaConfig {
    pub dir: PathBuf,
    pub common_name: String,
    pub organization: String,
    pub country: String,
    /// Validity, in days, for newly minted leaf certs.
    pub leaf_validity_days: u32,
    /// Validity, in days, for the root CA at generation time.
    pub root_validity_days: u32,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("./ca"),
            common_name: "Lancer Proxy CA".to_string(),
            organization: "Lancer".to_string(),
            country: "US".to_string(),
            leaf_validity_days: 397, // CA/B Forum max for public certs (we're private but use it)
            root_validity_days: 3650,
        }
    }
}

pub struct CertificateAuthority {
    pub config: CaConfig,
    /// The actual root certificate, kept loaded for fast leaf signing.
    cert_pem: Arc<str>,
    key_pem: Arc<str>,
    /// Parsed signing material for rcgen.
    issuer: rcgen::Issuer<'static, KeyPair>,
}

impl CertificateAuthority {
    /// Load an existing CA from disk, or generate a fresh one if none exists.
    pub fn load_or_create(config: CaConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.dir).context("creating CA dir")?;
        let cert_path = config.dir.join("ca.pem");
        let key_path = config.dir.join("ca.key");

        if cert_path.exists() && key_path.exists() {
            let cert_pem = std::fs::read_to_string(&cert_path).context("reading ca.pem")?;
            let key_pem = std::fs::read_to_string(&key_path).context("reading ca.key")?;
            let key_pair =
                KeyPair::from_pem(&key_pem).context("parsing existing CA private key")?;
            let issuer = rcgen::Issuer::from_ca_cert_pem(&cert_pem, key_pair)
                .context("parsing existing CA certificate")?;
            info!(?cert_path, "loaded existing Lancer CA");
            return Ok(Self {
                config,
                cert_pem: Arc::from(cert_pem),
                key_pem: Arc::from(key_pem),
                issuer,
            });
        }

        info!("no CA on disk — generating a new root CA");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, &config.common_name);
            dn.push(DnType::OrganizationName, &config.organization);
            dn.push(DnType::CountryName, &config.country);
            dn
        };
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(config.root_validity_days as i64);

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .context("generating CA keypair")?;
        let cert = params
            .self_signed(&key_pair)
            .context("self-signing CA cert")?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        std::fs::write(&cert_path, &cert_pem).context("writing ca.pem")?;
        std::fs::write(&key_path, &key_pem).context("writing ca.key")?;

        // re-parse so we own an `Issuer` we can sign with
        let signing_key =
            KeyPair::from_pem(&key_pem).context("re-parsing freshly written CA key")?;
        let issuer = rcgen::Issuer::from_ca_cert_pem(&cert_pem, signing_key)
            .context("re-parsing freshly written CA cert")?;
        Ok(Self {
            config,
            cert_pem: Arc::from(cert_pem),
            key_pem: Arc::from(key_pem),
            issuer,
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    /// Export the CA in DER form (useful for installation).
    pub fn der(&self) -> Result<Vec<u8>> {
        let mut iter = rustls_pemfile::certs(&mut self.cert_pem.as_bytes());
        let first = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("CA pem has no certificate"))??;
        Ok(first.as_ref().to_vec())
    }

    /// Mint a leaf certificate for the given hostname, signed by the CA.
    pub fn mint_leaf(&self, host: &str) -> Result<MintedLeaf> {
        let mut params = CertificateParams::new(vec![host.to_string()])
            .context("creating leaf params")?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        dn.push(DnType::OrganizationName, &self.config.organization);
        params.distinguished_name = dn;
        params.key_usages =
            vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(self.config.leaf_validity_days as i64);

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert = params.signed_by(&key_pair, &self.issuer)?;
        Ok(MintedLeaf {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        })
    }

    pub fn write_der(&self, path: impl AsRef<Path>) -> Result<()> {
        let der = self.der()?;
        std::fs::write(path, der)?;
        Ok(())
    }

    pub fn write_pem(&self, path: impl AsRef<Path>) -> Result<()> {
        std::fs::write(path, self.cert_pem.as_bytes())?;
        Ok(())
    }
}

/// A freshly generated leaf certificate and key.
pub struct MintedLeaf {
    pub cert_pem: String,
    pub key_pem: String,
}
