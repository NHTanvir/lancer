//! Insecure deserialization indicators (Java / .NET / PHP / Ruby / Python).

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;
use regex::Regex;

use crate::insertion::InsertionPoint;
use crate::ActiveCheck;

pub struct DeserializationCheck;

#[async_trait]
impl ActiveCheck for DeserializationCheck {
    fn id(&self) -> &'static str { "active.deserialization" }
    fn name(&self) -> &'static str { "Insecure deserialization candidate" }
    async fn run(&self, _client: &HttpClient, base: &HttpRequest, point: &InsertionPoint) -> Vec<Issue> {
        // We avoid sending exploit payloads — those are user-driven. Here we
        // look for serialized-object indicators in the *value* of the
        // insertion point.
        let v = &point.original_value;
        let java_rx = Regex::new(r"^rO0AB").unwrap(); // base64(0xACED 0x0005)
        let php_rx = Regex::new(r#"^O:\d+:"\w+":\d+:\{"#).unwrap();
        let dotnet_rx = Regex::new(r"AAEAAAD/////").unwrap();
        let python_pickle_rx = Regex::new(r"^(c__main__|c__builtin__|\x80\x04|gASV)").unwrap();
        let ruby_rx = Regex::new(r"^BAh7").unwrap();
        let (variant, conf) = if java_rx.is_match(v) {
            ("Java serialized object", Confidence::Firm)
        } else if php_rx.is_match(v) {
            ("PHP serialized object", Confidence::Firm)
        } else if dotnet_rx.is_match(v) {
            (".NET BinaryFormatter blob", Confidence::Firm)
        } else if python_pickle_rx.is_match(v) {
            ("Python pickle blob", Confidence::Tentative)
        } else if ruby_rx.is_match(v) {
            ("Ruby Marshal blob", Confidence::Tentative)
        } else {
            return Vec::new();
        };
        let mut i = Issue::new(base.meta.host.clone(), base.url(), "Insecure deserialization (likely)",
            Severity::High, conf,
            format!("parameter `{}` contains what appears to be a {variant}", point.name));
        i.remediation = Some("Stop deserializing untrusted input. If unavoidable, use a strict allow-list or signed payloads.".into());
        i.check_id = Some(self.id().into());
        vec![i]
    }
}
