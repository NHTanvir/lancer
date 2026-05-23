//! LDAP injection.

use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_storage::issues::{Confidence, Issue, Severity};
use lancer_tools::HttpClient;
use regex::Regex;

use crate::insertion::{substitute, InsertionPoint};
use crate::ActiveCheck;

pub struct LdapCheck;

const PROBES: &[&str] = &["*)(uid=*", "*)(|(uid=*", "*))%00", "admin*)(|(password=*"];

#[async_trait]
impl ActiveCheck for LdapCheck {
    fn id(&self) -> &'static str {
        "active.ldap"
    }
    fn name(&self) -> &'static str {
        "LDAP injection"
    }
    async fn run(
        &self,
        client: &HttpClient,
        base: &HttpRequest,
        point: &InsertionPoint,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        let err_rx = Regex::new(
            r"(?i)javax\.naming\.|InvalidDN|LDAPException|LdapErr|invalid filter|Bad search filter|com.sun.jndi.ldap",
        )
        .unwrap();
        for p in PROBES {
            let Some(req) = substitute(base, point, p) else { continue };
            let Ok(resp) = client.send(&req).await else { continue };
            let body = resp.body_text().unwrap_or("");
            if err_rx.is_match(body) {
                let mut i = Issue::new(
                    base.meta.host.clone(),
                    base.url(),
                    "LDAP injection",
                    Severity::High,
                    Confidence::Firm,
                    format!("payload `{p}` produced an LDAP error response"),
                );
                i.remediation = Some(
                    "Escape user input per RFC4515 before embedding into LDAP filter strings.".into(),
                );
                i.notes = Some(format!("insertion point: {} ({:?})", point.name, point.location));
                i.check_id = Some(self.id().into());
                issues.push(i);
                return issues;
            }
        }
        issues
    }
}
