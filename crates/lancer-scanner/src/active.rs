//! Active scan checks.

pub mod crlf;
pub mod open_redirect;
pub mod ssrf;
pub mod sqli;
pub mod traversal;
pub mod xss;

use std::sync::Arc;

use crate::ActiveCheck;

pub fn registry() -> Vec<Arc<dyn ActiveCheck>> {
    vec![
        Arc::new(sqli::SqliCheck),
        Arc::new(xss::XssCheck),
        Arc::new(traversal::TraversalCheck),
        Arc::new(open_redirect::OpenRedirectCheck),
        Arc::new(crlf::CrlfCheck),
        Arc::new(ssrf::SsrfCheck),
    ]
}
