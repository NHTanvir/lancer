//! Certificate authority management.
//!
//! On first run, Lancer generates a self-signed root CA, stores it on disk, and
//! uses it to mint per-host leaf certificates on demand. The CA is the only
//! thing the user has to import into their browser/system trust store.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaConfig {
    pub dir: PathBuf,
    pub common_name: String,
    pub organization: String,
    pub country: String,
    pub leaf_validity_days: u32,
    pub root_validity_days: u32,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("./ca"),
            common_name: "Lancer Proxy CA".to_string(),
            organization: "Lancer".to_string(),
            country: "US".to_string(),
            leaf_validity_days: 397,
            root_validity_days: 3650,
        }
    }
}

pub struct CertificateAuthority {
    pub config: CaConfig,
    cert_pem: Arc<str>,
    key_pem: Arc<str>,
    ca_cert: Certificate,
    ca_key: KeyPair,
}

impl CertificateAuthority {
    pub fn load_or_create(config: CaConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.dir).context("creating CA dir")?;
        let cert_path = config.dir.join("ca.pem");
        let key_path = config.dir.join("ca.key");

        if cert_path.exists() && key_path.exists() {
            let cert_pem = std::fs::read_to_string(&cert_path).context("reading ca.pem")?;
            let key_pem = std::fs::read_to_string(&key_path).context("reading ca.key")?;
            let ca_key = KeyPair::from_pem(&key_pem).context("parsing existing CA private key")?;
            let params = CertificateParams::from_ca_cert_pem(&cert_pem)
                .context("parsing existing CA certificate params")?;
            let ca_cert = params
                .self_signed(&ca_key)
                .context("rebuilding CA certificate from disk")?;
            info!(?cert_path, "loaded existing Lancer CA");
            return Ok(Self {
                config,
                cert_pem: Arc::from(cert_pem),
                key_pem: Arc::from(key_pem),
                ca_cert,
                ca_key,
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

        let ca_key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generating CA keypair")?;
        let ca_cert = params
            .self_signed(&ca_key)
            .context("self-signing CA cert")?;
        let cert_pem = ca_cert.pem();
        let key_pem = ca_key.serialize_pem();
        std::fs::write(&cert_path, &cert_pem).context("writing ca.pem")?;
        std::fs::write(&key_path, &key_pem).context("writing ca.key")?;

        Ok(Self {
            config,
            cert_pem: Arc::from(cert_pem),
            key_pem: Arc::from(key_pem),
            ca_cert,
            ca_key,
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    pub fn der(&self) -> Result<Vec<u8>> {
        let pem_bytes = self.cert_pem.as_bytes().to_vec();
        let mut slice = pem_bytes.as_slice();
        let mut iter = rustls_pemfile::certs(&mut slice);
        let first = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("CA pem has no certificate"))??;
        Ok(first.as_ref().to_vec())
    }

    pub fn mint_leaf(&self, host: &str) -> Result<MintedLeaf> {
        let mut params =
            CertificateParams::new(vec![host.to_string()]).context("creating leaf params")?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        dn.push(DnType::OrganizationName, &self.config.organization);
        params.distinguished_name = dn;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(self.config.leaf_validity_days as i64);

        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert = params.signed_by(&leaf_kp, &self.ca_cert, &self.ca_key)?;
        Ok(MintedLeaf {
            cert_pem: cert.pem(),
            key_pem: leaf_kp.serialize_pem(),
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

pub struct MintedLeaf {
    pub cert_pem: String,
    pub key_pem: String,
}
