//! Active scan checks.

pub mod cache_poison;
pub mod clickjacking;
pub mod cmd_injection;
pub mod cors;
pub mod crlf;
pub mod deserialization;
pub mod graphql;
pub mod host_header;
pub mod jwt;
pub mod ldap;
pub mod mass_assignment;
pub mod nosqli;
pub mod oauth;
pub mod open_redirect;
pub mod proto_pollution;
pub mod race;
pub mod react2shell;
pub mod ssrf;
pub mod sqli;
pub mod smuggling;
pub mod ssti;
pub mod subdomain_takeover;
pub mod traversal;
pub mod web_llm;
pub mod xpath;
pub mod xss;
pub mod xxe;

use std::sync::Arc;

use crate::ActiveCheck;

pub fn registry() -> Vec<Arc<dyn ActiveCheck>> {
    vec![
        Arc::new(sqli::SqliCheck),
        Arc::new(nosqli::NoSqliCheck),
        Arc::new(xss::XssCheck),
        Arc::new(traversal::TraversalCheck),
        Arc::new(open_redirect::OpenRedirectCheck),
        Arc::new(crlf::CrlfCheck),
        Arc::new(ssrf::SsrfCheck),
        Arc::new(cmd_injection::CommandInjectionCheck),
        Arc::new(ssti::SstiCheck),
        Arc::new(ldap::LdapCheck),
        Arc::new(xpath::XPathCheck),
        Arc::new(host_header::HostHeaderCheck),
        Arc::new(cors::CorsCheck),
        Arc::new(jwt::JwtCheck),
        Arc::new(graphql::GraphQlCheck),
        Arc::new(subdomain_takeover::SubdomainTakeoverCheck),
        Arc::new(mass_assignment::MassAssignmentCheck),
        Arc::new(xxe::XxeCheck),
        Arc::new(smuggling::SmugglingCheck),
        Arc::new(cache_poison::CachePoisonCheck),
        Arc::new(clickjacking::ClickjackingCheck),
        Arc::new(deserialization::DeserializationCheck),
        Arc::new(proto_pollution::ProtoPollutionCheck),
        Arc::new(race::RaceConditionCheck),
        Arc::new(oauth::OAuthCheck),
        Arc::new(web_llm::WebLlmCheck),
        Arc::new(react2shell::React2ShellCheck),
    ]
}
