//! Hostname-resolution overrides — DNS-over-Lancer for testing virtual hosts
//! and pinning a target host to a specific IP.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsOverride {
    pub host: String,
    pub ip: IpAddr,
}

#[derive(Default, Debug, Clone)]
pub struct DnsTable {
    overrides: Arc<ArcSwap<HashMap<String, IpAddr>>>,
}

impl DnsTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn replace(&self, items: Vec<DnsOverride>) {
        let map: HashMap<String, IpAddr> = items
            .into_iter()
            .map(|o| (o.host.to_ascii_lowercase(), o.ip))
            .collect();
        self.overrides.store(Arc::new(map));
    }

    pub fn resolve(&self, host: &str) -> Option<IpAddr> {
        self.overrides.load().get(&host.to_ascii_lowercase()).copied()
    }

    pub fn all(&self) -> Vec<DnsOverride> {
        self.overrides
            .load()
            .iter()
            .map(|(h, ip)| DnsOverride { host: h.clone(), ip: *ip })
            .collect()
    }
}
