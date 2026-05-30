//! §49 URL Pipeline Toolkit — qsreplace / gf / anew / uro / unfurl bundled into Lancer.
//!
//! All five accept stdin, emit stdout — chainable:
//!   `cat urls.txt | lancer url uro | lancer url gf xss | lancer url qsreplace '"><svg' | lancer url anew tested.txt`

use clap::Subcommand;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};

#[derive(Debug, Subcommand)]
pub enum UrlsCmd {
    /// Replace every query-string value with `<NEW_VALUE>`.
    Qsreplace { new_value: String },
    /// Grep for predefined patterns from ~/.lancer/patterns.
    Gf { pattern: String },
    /// Stream-dedup: print only lines not already in `<FILE>`, append to file.
    Anew { file: String },
    /// Normalize URLs (remove sessions/tracking params, lowercase host, sort query).
    Uro,
    /// Extract `domain`, `path`, `query`, `scheme`, `fragment`, `port` from a URL stream.
    Unfurl { part: String },
    /// List bundled gf patterns.
    GfList,
}

pub fn run(cmd: UrlsCmd) -> anyhow::Result<()> {
    match cmd {
        UrlsCmd::Qsreplace { new_value }   => run_qsreplace(&new_value),
        UrlsCmd::Gf { pattern }            => run_gf(&pattern),
        UrlsCmd::Anew { file }             => run_anew(&file),
        UrlsCmd::Uro                       => run_uro(),
        UrlsCmd::Unfurl { part }           => run_unfurl(&part),
        UrlsCmd::GfList                    => { for n in pattern_names() { println!("{n}"); } Ok(()) },
    }
}

// ── qsreplace ────────────────────────────────────────────────────────────────

fn run_qsreplace(new_value: &str) -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let url = line?;
        writeln!(out, "{}", qsreplace_one(&url, new_value))?;
    }
    Ok(())
}

fn qsreplace_one(url: &str, new_value: &str) -> String {
    let Some(qpos) = url.find('?') else { return url.to_string(); };
    let (base, query) = url.split_at(qpos);
    let query = &query[1..]; // skip '?'
    let (qs, frag) = match query.find('#') {
        Some(p) => (&query[..p], &query[p..]),
        None => (query, ""),
    };
    let new_qs: Vec<String> = qs.split('&').filter_map(|kv| {
        let mut it = kv.splitn(2, '=');
        let k = it.next()?;
        if k.is_empty() { return None; }
        Some(format!("{k}={new_value}"))
    }).collect();
    format!("{base}?{}{frag}", new_qs.join("&"))
}

// ── gf ───────────────────────────────────────────────────────────────────────

fn pattern_names() -> Vec<&'static str> {
    vec![
        "xss", "sqli", "ssrf", "redirect", "lfi", "rce", "ssti",
        "jsvar", "interesting-subs", "interesting-params", "interesting-ext",
        "img-traversal", "graphql", "soap", "url-in-query", "debug-pages",
        "s3-buckets", "firebase", "meg-headers", "cors",
    ]
}

fn run_gf(pattern: &str) -> anyhow::Result<()> {
    let re = compile_gf(pattern)?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if re.is_match(&line) {
            writeln!(out, "{line}")?;
        }
    }
    Ok(())
}

fn compile_gf(name: &str) -> anyhow::Result<regex::Regex> {
    let pat = match name {
        "xss"                 => r"(?i)[?&](q|s|search|id|lang|keyword|query|callback|jsonp|target|user|first|name|url)=",
        "sqli"                => r"(?i)[?&](id|select|union|where|page|category)=",
        "ssrf"                => r"(?i)[?&](url|uri|path|continue|next|dest|destination|redirect|redir|file|reference)=",
        "redirect"            => r"(?i)[?&](redirect|return|next|target|rurl|continue|callback|jump|url)=",
        "lfi"                 => r"(?i)[?&](include|file|page|template|conf|config|path|tpl)=",
        "rce"                 => r"(?i)[?&](cmd|exec|command|jump|code|do)=",
        "ssti"                => r"(?i)\{\{.+?\}\}|\$\{.+?\}",
        "jsvar"               => r"(?i)\.js(\?.*)?$",
        "interesting-subs"    => r"(?i)\b(api|dev|test|stage|admin|internal|beta|qa|preprod)\.[a-z0-9.-]+\.[a-z]{2,}",
        "interesting-params"  => r"(?i)[?&](api_key|apikey|token|auth|password|secret|key|debug|test)=",
        "interesting-ext"     => r"(?i)\.(php|asp|aspx|jsp|jspx|cgi|cfm|json|xml|env|bak|swp|old|orig|conf|config|log|sql|db|pem|key)(\?|$)",
        "img-traversal"       => r"(?i)\.\.[\\/]+|%2e%2e[\\/]+",
        "graphql"             => r"(?i)/(graphql|graphiql|altair|playground|api/graphql)\b",
        "soap"                => r"(?i)\.(wsdl|asmx)(\?|$)",
        "url-in-query"        => r"=https?:%2F%2F|=https?:\/\/",
        "debug-pages"         => r"(?i)/(actuator|debug|trace|status|metrics|healthz|.git|.svn|.env|.aws|backup)\b",
        "s3-buckets"          => r"(?i)\.s3[.-][a-z0-9.-]*amazonaws\.com|/[a-z0-9.-]+\.s3\.amazonaws\.com",
        "firebase"            => r"(?i)\.firebaseio\.com|\.firebaseapp\.com",
        "meg-headers"         => r"(?i)set-cookie|location|server|x-powered-by",
        "cors"                => r"(?i)access-control-allow-(origin|credentials)",
        _ => anyhow::bail!("unknown gf pattern: {name}"),
    };
    Ok(regex::Regex::new(pat)?)
}

// ── anew ─────────────────────────────────────────────────────────────────────

fn run_anew(file: &str) -> anyhow::Result<()> {
    let mut seen: HashSet<String> = HashSet::new();
    if let Ok(f) = std::fs::File::open(file) {
        for line in BufReader::new(f).lines() {
            if let Ok(l) = line { seen.insert(l); }
        }
    }
    let mut sink = std::fs::OpenOptions::new()
        .create(true).append(true).open(file)?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let l = line?;
        if seen.insert(l.clone()) {
            writeln!(out, "{l}")?;
            writeln!(sink, "{l}")?;
        }
    }
    Ok(())
}

// ── uro ──────────────────────────────────────────────────────────────────────

fn run_uro() -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut seen: HashSet<String> = HashSet::new();
    for line in stdin.lock().lines() {
        let l = line?;
        let norm = uro_one(&l);
        if seen.insert(norm.clone()) {
            writeln!(out, "{norm}")?;
        }
    }
    Ok(())
}

fn uro_one(url: &str) -> String {
    // Lowercase host, trim trailing slash, sort query, drop session/tracking params.
    let blacklist = [
        "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
        "fbclid", "gclid", "yclid", "msclkid", "ref", "ref_src", "ref_url",
        "sessionid", "sid", "phpsessid", "jsessionid",
    ];
    let Ok(mut u) = url::Url::parse(url) else { return url.to_string() };
    let host = u.host_str().unwrap_or("").to_lowercase();
    let _ = u.set_host(Some(&host));
    let new_q: Vec<(String, String)> = u.query_pairs()
        .filter(|(k, _)| !blacklist.contains(&k.to_lowercase().as_str()))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut sorted = new_q.clone();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    u.set_query(None);
    if !sorted.is_empty() {
        let qs = sorted.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
        u.set_query(Some(&qs));
    }
    let mut s = u.to_string();
    if let Some(stripped) = s.strip_suffix('/') {
        if u.path().len() > 1 { s = stripped.to_string(); }
    }
    s
}

// ── unfurl ───────────────────────────────────────────────────────────────────

fn run_unfurl(part: &str) -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let l = line?;
        if let Some(extracted) = unfurl_one(&l, part) {
            writeln!(out, "{extracted}")?;
        }
    }
    Ok(())
}

fn unfurl_one(url: &str, part: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    match part {
        "domain" | "host"  => u.host_str().map(|s| s.to_string()),
        "path"             => Some(u.path().to_string()),
        "query"            => u.query().map(|s| s.to_string()),
        "scheme"           => Some(u.scheme().to_string()),
        "fragment"         => u.fragment().map(|s| s.to_string()),
        "port"             => u.port().map(|p| p.to_string()),
        "keys"             => Some(u.query_pairs().map(|(k, _)| k.to_string()).collect::<Vec<_>>().join("\n")),
        "values"           => Some(u.query_pairs().map(|(_, v)| v.to_string()).collect::<Vec<_>>().join("\n")),
        _                  => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn qsreplace_basic() {
        assert_eq!(qsreplace_one("https://x.com?a=1&b=2", "X"), "https://x.com?a=X&b=X");
    }
    #[test]
    fn uro_dedups() {
        assert_eq!(uro_one("https://X.COM/a/?utm_source=g&q=1"), "https://x.com/a?q=1");
    }
    #[test]
    fn unfurl_host() {
        assert_eq!(unfurl_one("https://x.com:8080/a?b=1", "host"), Some("x.com".into()));
        assert_eq!(unfurl_one("https://x.com:8080/a?b=1", "port"), Some("8080".into()));
    }
}
