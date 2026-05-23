//! Parse the most common IaC files for additional attack surface.

use anyhow::Result;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurface {
    pub exposed_ports: Vec<u16>,
    pub services: Vec<String>,
    pub env_secrets_likely: Vec<String>,
    pub volumes: Vec<String>,
    pub notes: Vec<String>,
}

impl AttackSurface {
    pub fn merge(&mut self, other: AttackSurface) {
        self.exposed_ports.extend(other.exposed_ports);
        self.services.extend(other.services);
        self.env_secrets_likely.extend(other.env_secrets_likely);
        self.volumes.extend(other.volumes);
        self.notes.extend(other.notes);
        self.exposed_ports.sort();
        self.exposed_ports.dedup();
    }
}

static EXPOSE_RX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*EXPOSE\s+(\d+)").unwrap());
static FROM_RX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*FROM\s+(\S+)").unwrap());
static ENV_RX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)^\s*ENV\s+(\w+)\s*[=\s]\s*(.+)"#).unwrap());
static VOLUME_RX: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)^\s*VOLUME\s+(.+)"#).unwrap());

pub fn parse_dockerfile(body: &str) -> AttackSurface {
    let mut s = AttackSurface { exposed_ports: vec![], services: vec![], env_secrets_likely: vec![], volumes: vec![], notes: vec![] };
    for line in body.lines() {
        if let Some(cap) = EXPOSE_RX.captures(line) {
            if let Ok(p) = cap[1].parse() {
                s.exposed_ports.push(p);
            }
        }
        if let Some(cap) = FROM_RX.captures(line) {
            s.services.push(cap[1].to_string());
        }
        if let Some(cap) = ENV_RX.captures(line) {
            let name = cap[1].to_ascii_lowercase();
            if name.contains("secret") || name.contains("password") || name.contains("token") || name.contains("key") {
                s.env_secrets_likely.push(cap[1].to_string());
            }
        }
        if let Some(cap) = VOLUME_RX.captures(line) {
            s.volumes.push(cap[1].trim().to_string());
        }
    }
    s
}

pub fn parse_compose(body: &str) -> Result<AttackSurface> {
    let v: serde_yaml::Value = serde_yaml::from_str(body)?;
    let mut s = AttackSurface { exposed_ports: vec![], services: vec![], env_secrets_likely: vec![], volumes: vec![], notes: vec![] };
    let Some(services) = v.get("services").and_then(|x| x.as_mapping()) else { return Ok(s) };
    for (name_v, body_v) in services {
        let name = name_v.as_str().unwrap_or("").to_string();
        s.services.push(name.clone());
        if let Some(ports) = body_v.get("ports").and_then(|x| x.as_sequence()) {
            for p in ports {
                let raw = match p {
                    serde_yaml::Value::String(s) => s.clone(),
                    serde_yaml::Value::Number(n) => n.to_string(),
                    _ => continue,
                };
                if let Some(left) = raw.split(':').next() {
                    if let Ok(port) = left.parse() {
                        s.exposed_ports.push(port);
                    }
                }
            }
        }
        if let Some(env) = body_v.get("environment") {
            walk_env(env, &mut s);
        }
    }
    Ok(s)
}

fn walk_env(v: &serde_yaml::Value, s: &mut AttackSurface) {
    match v {
        serde_yaml::Value::Mapping(m) => {
            for (k, _) in m {
                if let Some(key) = k.as_str() {
                    classify_env_name(key, s);
                }
            }
        }
        serde_yaml::Value::Sequence(arr) => {
            for item in arr {
                if let Some(s_str) = item.as_str() {
                    let key = s_str.split('=').next().unwrap_or("");
                    classify_env_name(key, s);
                }
            }
        }
        _ => {}
    }
}

fn classify_env_name(name: &str, s: &mut AttackSurface) {
    let lower = name.to_ascii_lowercase();
    if lower.contains("secret") || lower.contains("password") || lower.contains("token") || lower.contains("key") {
        s.env_secrets_likely.push(name.to_string());
    }
}

pub fn parse_kubernetes(body: &str) -> Result<AttackSurface> {
    let mut s = AttackSurface { exposed_ports: vec![], services: vec![], env_secrets_likely: vec![], volumes: vec![], notes: vec![] };
    for doc in serde_yaml::Deserializer::from_str(body) {
        let v = serde_yaml::Value::deserialize(doc)?;
        let kind = v.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        let name = v.get("metadata").and_then(|m| m.get("name")).and_then(|n| n.as_str()).unwrap_or("");
        s.services.push(format!("{kind}/{name}"));
        if kind == "Service" {
            if let Some(ports) = v.get("spec").and_then(|sp| sp.get("ports")).and_then(|p| p.as_sequence()) {
                for p in ports {
                    if let Some(port) = p.get("port").and_then(|x| x.as_u64()) {
                        s.exposed_ports.push(port as u16);
                    }
                }
            }
        }
    }
    Ok(s)
}

pub fn parse_terraform(body: &str) -> AttackSurface {
    let mut s = AttackSurface { exposed_ports: vec![], services: vec![], env_secrets_likely: vec![], volumes: vec![], notes: vec![] };
    let resource_rx = Regex::new(r#"resource\s+"([^"]+)"\s+"([^"]+)""#).unwrap();
    for cap in resource_rx.captures_iter(body) {
        let kind = &cap[1];
        let name = &cap[2];
        if kind.contains("security_group") || kind.contains("firewall") {
            s.notes.push(format!("review {kind}.{name} firewall rules"));
        }
        if kind.contains("load_balancer") || kind.contains("alb") || kind.contains("nlb") {
            s.services.push(format!("{kind}.{name} (load balancer)"));
        }
        if kind.contains("s3_bucket") || kind.contains("storage_bucket") {
            s.notes.push(format!("verify {kind}.{name} access policy is private"));
        }
    }
    // Port hints
    for cap in Regex::new(r#"from_port\s*=\s*(\d+)"#).unwrap().captures_iter(body) {
        if let Ok(p) = cap[1].parse() {
            s.exposed_ports.push(p);
        }
    }
    s.exposed_ports.sort();
    s.exposed_ports.dedup();
    s
}
