//! Passive scan checks.

pub mod cookies;
pub mod headers;
pub mod info_disclosure;
pub mod js_secrets;
pub mod mixed_content;
pub mod software_disclosure;
pub mod tls_config;

use std::sync::Arc;

use lancer_core::HttpRequest;
use lancer_storage::issues::Issue;

use crate::PassiveCheck;

pub fn registry() -> Vec<Arc<dyn PassiveCheck>> {
    vec![
        Arc::new(headers::SecurityHeaderCheck),
        Arc::new(cookies::CookieFlagCheck),
        Arc::new(info_disclosure::InfoDisclosureCheck),
        Arc::new(js_secrets::JsSecretCheck),
        Arc::new(mixed_content::MixedContentCheck),
        Arc::new(software_disclosure::SoftwareDisclosureCheck),
        Arc::new(tls_config::TlsConfigurationCheck),
    ]
}

pub(crate) fn issue(
    name: &str,
    severity: lancer_storage::issues::Severity,
    confidence: lancer_storage::issues::Confidence,
    request: &HttpRequest,
    description: impl Into<String>,
    remediation: Option<&str>,
) -> Issue {
    let mut i = Issue::new(
        request.meta.host.clone(),
        request.url(),
        name,
        severity,
        confidence,
        description,
    );
    i.remediation = remediation.map(|s| s.to_string());
    i
}
