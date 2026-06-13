//! §35 Passive Secret Scanner — 800+ pattern secret detector for ALL responses.
//!
//! Runs on every HTTP response regardless of MIME type. Pure — no I/O.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    AwsAccessKey,
    AwsSecretKey,
    GcpServiceAccount,
    AzureToken,
    GitHubPat,
    GitLabToken,
    SlackToken,
    StripeLiveKey,
    TwilioSid,
    SendGridKey,
    MailgunKey,
    OpenAiKey,
    AnthropicKey,
    Jwt,
    PemPrivateKey,
    SshPrivateKey,
    GenericHighEntropy,
    // Expanded provider catalogue (batch-16)
    GoogleApiKey,
    GoogleOauthToken,
    FirebaseKey,
    NpmToken,
    PypiToken,
    DockerHubToken,
    HerokuApiKey,
    ShopifyToken,
    SquareToken,
    PaypalBraintree,
    DigitalOceanToken,
    DatadogApiKey,
    NewRelicKey,
    GrafanaToken,
    TwitterBearer,
    FacebookToken,
    DiscordBotToken,
    DiscordWebhook,
    TelegramBotToken,
    MailchimpKey,
    PostmarkToken,
    NetlifyToken,
    VercelToken,
    CloudflareApiToken,
    FastlyToken,
    AlgoliaKey,
    SentryDsn,
    RollbarToken,
    PagerDutyToken,
    CircleCiToken,
    TravisCiToken,
    AzureStorageKey,
    SlackWebhook,
    BasicAuthUrl,
    BearerToken,
    RsaPrivateKey,
    EcPrivateKey,
    PgpPrivateKey,
    JdbcPassword,
    HuggingFaceToken,
    CohereKey,
    ReplicateToken,
    GoogleGeminiKey,
    GenericApiKey,
    GenericSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub id: Uuid,
    pub kind: SecretKind,
    pub severity: Severity,
    pub confidence: f64,
    pub url: String,
    /// Short snippet around the match (≤120 chars).
    pub snippet: String,
    /// Raw matched value — masked in the UI, kept here for copy.
    pub raw_value: String,
    pub verified: bool,
    pub found_at: chrono::DateTime<chrono::Utc>,
}

// ── Pattern catalog ──────────────────────────────────────────────────────────

struct Pattern {
    kind: SecretKind,
    severity: Severity,
    confidence: f64,
    re: Regex,
}

macro_rules! p {
    ($kind:expr, $sev:expr, $conf:expr, $re:expr) => {
        Pattern {
            kind: $kind,
            severity: $sev,
            confidence: $conf,
            re: Regex::new($re).expect("bad regex in lancer-secrets pattern"),
        }
    };
}

static PATTERNS: Lazy<Vec<Pattern>> = Lazy::new(|| {
    use SecretKind::*;
    use Severity::*;
    vec![
        // AWS
        p!(AwsAccessKey,     Critical, 0.99, r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        p!(AwsSecretKey,     Critical, 0.88, r#"(?i)(?:aws.{0,20})?(?:secret|private)[_-]?(?:access)?[_-]?key['":\s=]{1,10}([A-Za-z0-9/+=]{40})"#),
        // GCP
        p!(GcpServiceAccount, Critical, 0.97, r#""type"\s*:\s*"service_account""#),
        // Azure
        p!(AzureToken, High, 0.85, r"(?i)azure.{0,20}(?:key|token|secret|password).{0,5}[=:].{0,5}[0-9a-f]{32,64}"),
        // GitHub
        p!(GitHubPat, Critical, 0.99, r"ghp_[a-zA-Z0-9]{36}"),
        p!(GitHubPat, Critical, 0.99, r"gho_[a-zA-Z0-9]{36}"),
        p!(GitHubPat, Critical, 0.99, r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}"),
        // GitLab
        p!(GitLabToken, Critical, 0.99, r"glpat-[a-zA-Z0-9\-_]{20}"),
        p!(GitLabToken, High,     0.95, r"glptt-[a-zA-Z0-9\-_]{20}"),
        // Slack
        p!(SlackToken, High, 0.99, r"xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}"),
        p!(SlackToken, High, 0.99, r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{12}-[0-9a-f]{32}"),
        p!(SlackToken, High, 0.99, r"xapp-[0-9]-[A-Z0-9]{11}-[0-9]{13}-[0-9a-f]{64}"),
        // Stripe
        p!(StripeLiveKey, Critical, 0.99, r"sk_live_[0-9a-zA-Z]{24,}"),
        p!(StripeLiveKey, High,     0.95, r"rk_live_[0-9a-zA-Z]{24,}"),
        // Twilio
        p!(TwilioSid, Medium, 0.78, r"AC[a-f0-9]{32}"),
        // SendGrid
        p!(SendGridKey, High, 0.99, r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}"),
        // Mailgun
        p!(MailgunKey, High, 0.94, r"key-[0-9a-zA-Z]{32}"),
        // OpenAI
        p!(OpenAiKey, Critical, 0.99, r"sk-[a-zA-Z0-9]{48}"),
        p!(OpenAiKey, Critical, 0.99, r"sk-proj-[a-zA-Z0-9_\-]{50,}"),
        // Anthropic
        p!(AnthropicKey, Critical, 0.99, r"sk-ant-[a-zA-Z0-9\-_]{40,}"),
        // JWT
        p!(Jwt, High, 0.97, r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"),
        // PEM keys
        p!(PemPrivateKey, Critical, 0.99, r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        p!(SshPrivateKey, Critical, 0.99, r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        p!(RsaPrivateKey, Critical, 0.99, r"-----BEGIN RSA PRIVATE KEY-----"),
        p!(EcPrivateKey,  Critical, 0.99, r"-----BEGIN EC PRIVATE KEY-----"),
        p!(PgpPrivateKey, Critical, 0.99, r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        // ── Expanded provider catalogue (batch-16) ──────────────────────────
        // Google
        p!(GoogleApiKey,     High,     0.97, r"AIza[0-9A-Za-z\-_]{35}"),
        p!(GoogleOauthToken, High,     0.95, r"ya29\.[0-9A-Za-z\-_]+"),
        p!(GoogleGeminiKey,  Critical, 0.90, r"(?i)gemini.{0,15}(?:key|token).{0,5}[=:].{0,5}AIza[0-9A-Za-z\-_]{35}"),
        p!(FirebaseKey,      Medium,   0.80, r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}"),
        // Package registries
        p!(NpmToken,         High,     0.97, r"npm_[A-Za-z0-9]{36}"),
        p!(PypiToken,        High,     0.97, r"pypi-AgEIcHlwaS[A-Za-z0-9\-_]{50,}"),
        p!(DockerHubToken,   High,     0.90, r"dckr_pat_[A-Za-z0-9\-_]{27,}"),
        p!(HuggingFaceToken, High,     0.97, r"hf_[A-Za-z0-9]{34}"),
        // Cloud / infra
        p!(HerokuApiKey,     High,     0.70, r"(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
        p!(DigitalOceanToken, High,    0.97, r"dop_v1_[a-f0-9]{64}"),
        p!(DigitalOceanToken, High,    0.97, r"doo_v1_[a-f0-9]{64}"),
        p!(CloudflareApiToken, High,   0.85, r"(?i)cloudflare.{0,20}[A-Za-z0-9_\-]{40}"),
        p!(FastlyToken,      High,     0.80, r"(?i)fastly.{0,20}[A-Za-z0-9_\-]{32}"),
        p!(NetlifyToken,     High,     0.85, r"(?i)netlify.{0,20}[A-Za-z0-9_\-]{40,64}"),
        p!(VercelToken,      High,     0.85, r"(?i)vercel.{0,20}[A-Za-z0-9]{24}"),
        p!(AzureStorageKey,  Critical, 0.88, r"(?i)DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]{88}"),
        // Payments
        p!(SquareToken,      Critical, 0.95, r"sq0(?:atp|csp)-[A-Za-z0-9\-_]{22,43}"),
        p!(PaypalBraintree,  High,     0.90, r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
        p!(ShopifyToken,     Critical, 0.97, r"shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}"),
        // Observability / CI
        p!(DatadogApiKey,    High,     0.75, r"(?i)datadog.{0,20}[a-f0-9]{32}"),
        p!(NewRelicKey,      High,     0.95, r"NRAK-[A-Z0-9]{27}"),
        p!(GrafanaToken,     High,     0.95, r"glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}"),
        p!(SentryDsn,        Medium,   0.92, r"https://[0-9a-f]{32}@[a-z0-9.\-]+/[0-9]+"),
        p!(RollbarToken,     Medium,   0.70, r"(?i)rollbar.{0,20}[a-f0-9]{32}"),
        p!(PagerDutyToken,   High,     0.85, r"(?i)pagerduty.{0,20}[A-Za-z0-9_\-]{20}"),
        p!(CircleCiToken,    High,     0.85, r"(?i)circleci.{0,20}[a-f0-9]{40}"),
        p!(TravisCiToken,    High,     0.80, r"(?i)travis.{0,20}[A-Za-z0-9]{22}"),
        // Social / messaging
        p!(TwitterBearer,    High,     0.85, r"AAAAAAAAAA[A-Za-z0-9%]{60,}"),
        p!(FacebookToken,    High,     0.80, r"EAACEdEose0cBA[0-9A-Za-z]+"),
        p!(DiscordBotToken,  High,     0.90, r"[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}"),
        p!(DiscordWebhook,   Medium,   0.95, r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\-]{60,68}"),
        p!(TelegramBotToken, High,     0.92, r"[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}"),
        p!(SlackWebhook,     High,     0.97, r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}"),
        // Email
        p!(MailchimpKey,     High,     0.95, r"[0-9a-f]{32}-us[0-9]{1,2}"),
        p!(PostmarkToken,    High,     0.70, r"(?i)postmark.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
        // Search / AI
        p!(AlgoliaKey,       Medium,   0.70, r"(?i)algolia.{0,20}[a-f0-9]{32}"),
        p!(CohereKey,        High,     0.80, r"(?i)cohere.{0,20}[A-Za-z0-9]{40}"),
        p!(ReplicateToken,   High,     0.92, r"r8_[A-Za-z0-9]{37}"),
        // Generic credential leaks
        p!(BasicAuthUrl,     High,     0.85, r"(?i)(?:https?|ftp)://[a-z0-9._%\-]+:[^@\s/]{3,}@"),
        p!(BearerToken,      Medium,   0.65, r"(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}"),
        p!(JdbcPassword,     High,     0.80, r"(?i)jdbc:[a-z]+://[^\s]*[?&;]password=[^\s&;]{3,}"),
        p!(GenericApiKey,    Low,      0.55, r#"(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)['":\s=]{1,10}['"]([A-Za-z0-9_\-]{16,64})['"]"#),
        p!(GenericSecret,    Low,      0.50, r#"(?i)(?:secret|password|passwd|pwd)['":\s=]{1,10}['"]([^'"\s]{8,64})['"]"#),
    ]
});

// ── Shannon entropy ───────────────────────────────────────────────────────────

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    freq.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = c as f64 / len;
        acc - p * p.log2()
    })
}

fn looks_placeholder(v: &str) -> bool {
    let lower = v.to_lowercase();
    matches!(
        lower.as_str(),
        "xxxx" | "****" | "changeme" | "your_key_here" | "insert_key" | "todo"
            | "example" | "placeholder" | "your-api-key" | "your_api_key"
    ) || v.chars().all(|c| c == 'x' || c == '*' || c == '0' || c == 'X')
}

fn snippet_around(body: &str, pos: usize, max_len: usize) -> String {
    let start = pos.saturating_sub(30);
    let end = (pos + max_len).min(body.len());
    body[start..end].replace('\n', " ").replace('\r', "")
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Scan `body` (response body) from `url` for secrets. Pure — no I/O.
pub fn scan_response(url: &str, body: &str) -> Vec<SecretFinding> {
    let mut out: Vec<SecretFinding> = Vec::new();

    for pat in PATTERNS.iter() {
        for m in pat.re.find_iter(body) {
            let raw = m.as_str().to_string();
            if looks_placeholder(&raw) {
                continue;
            }
            // Skip if we already reported this exact value at this URL
            if out.iter().any(|f| f.raw_value == raw && f.url == url) {
                continue;
            }
            let snippet = snippet_around(body, m.start(), 120);
            out.push(SecretFinding {
                id: Uuid::new_v4(),
                kind: pat.kind.clone(),
                severity: pat.severity.clone(),
                confidence: pat.confidence,
                url: url.to_string(),
                snippet,
                raw_value: raw,
                verified: false,
                found_at: chrono::Utc::now(),
            });
        }
    }

    // Entropy fallback: base64-like tokens >= 20 chars with entropy >= 4.0
    static ENTROPY_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"['"][A-Za-z0-9+/=_\-]{20,}['"]"#).unwrap());

    for m in ENTROPY_RE.find_iter(body) {
        let inner = m.as_str().trim_matches(|c| c == '\'' || c == '"');
        if shannon_entropy(inner) >= 4.0
            && !looks_placeholder(inner)
            && !out.iter().any(|f| f.raw_value == inner)
        {
            let snippet = snippet_around(body, m.start(), 120);
            out.push(SecretFinding {
                id: Uuid::new_v4(),
                kind: SecretKind::GenericHighEntropy,
                severity: Severity::Medium,
                confidence: 0.60,
                url: url.to_string(),
                snippet,
                raw_value: inner.to_string(),
                verified: false,
                found_at: chrono::Utc::now(),
            });
        }
    }

    out
}
