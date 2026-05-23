//! Per-host leaf-certificate cache. Generating a leaf takes a few ms; for a
//! site that needs hundreds of certs (many subdomains) we want this to be
//! effectively instant on hit.

use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tracing::debug;

use crate::ca::CertificateAuthority;

#[derive(Debug, Clone)]
struct CachedCert {
    server_config: Arc<ServerConfig>,
}

pub struct CertCache {
    ca: Arc<CertificateAuthority>,
    cache: DashMap<String, CachedCert>,
}

impl CertCache {
    pub fn new(ca: Arc<CertificateAuthority>) -> Self {
        Self { ca, cache: DashMap::new() }
    }

    /// Get a TLS `ServerConfig` for the given host, generating one on miss.
    pub fn server_config_for(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let key = canonical_host(host);
        if let Some(c) = self.cache.get(&key) {
            return Ok(c.server_config.clone());
        }
        debug!(host, "minting leaf cert");
        let leaf = self.ca.mint_leaf(&key)?;
        let server_config = build_server_config(&leaf.cert_pem, &leaf.key_pem, self.ca.cert_pem())?;
        let entry = CachedCert { server_config: server_config.clone() };
        self.cache.insert(key, entry);
        Ok(server_config)
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn clear(&self) {
        self.cache.clear();
    }
}

fn canonical_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn build_server_config(
    leaf_pem: &str,
    key_pem: &str,
    ca_pem: &str,
) -> Result<Arc<ServerConfig>> {
    let leaf_chain = read_certs(leaf_pem)?;
    let mut chain = leaf_chain;
    // also include the CA cert in the chain so clients can verify if they want
    let mut ca_chain = read_certs(ca_pem)?;
    chain.append(&mut ca_chain);
    let key = read_private_key(key_pem)?;
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

fn read_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut out = Vec::new();
    for item in rustls_pemfile::certs(&mut pem.as_bytes()) {
        out.push(item?);
    }
    Ok(out)
}

fn read_private_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    if let Some(k) = rustls_pemfile::pkcs8_private_keys(&mut pem.as_bytes()).next() {
        return Ok(PrivateKeyDer::Pkcs8(k?));
    }
    if let Some(k) = rustls_pemfile::ec_private_keys(&mut pem.as_bytes()).next() {
        return Ok(PrivateKeyDer::Sec1(k?));
    }
    if let Some(k) = rustls_pemfile::rsa_private_keys(&mut pem.as_bytes()).next() {
        return Ok(PrivateKeyDer::Pkcs1(k?));
    }
    anyhow::bail!("no private key found in pem");
}
