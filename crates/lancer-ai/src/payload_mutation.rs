//! AI-driven payload mutation hook for Intruder.
//!
//! Given a base payload that almost-worked (e.g., the response was 500), ask
//! the configured LLM to suggest mutations to try next. The provider plumbing
//! lives in `lancer_ai::LlmProvider`; this module just builds the prompt and
//! parses the model's reply into a Vec<String> of candidate payloads.

use anyhow::Result;

use crate::{LlmMessage, LlmProvider, LlmRequest};

const SYSTEM: &str = "You are an application-security tester. Given a payload that nearly worked, suggest 5 mutations that might succeed. Respond as a JSON array of strings; no commentary.";

pub async fn mutate(
    provider: &dyn LlmProvider,
    base_payload: &str,
    context: &str,
) -> Result<Vec<String>> {
    let prompt = format!(
        "Base payload: `{base_payload}`\nContext: {context}\nSuggest 5 mutations as JSON array."
    );
    let req = LlmRequest {
        model: default_model(provider.id()),
        messages: vec![LlmMessage { role: "user".into(), content: prompt }],
        system: Some(SYSTEM.into()),
        max_tokens: Some(512),
        temperature: Some(0.8),
    };
    let resp = provider.complete(&req).await?;
    let text = resp.content.trim();
    let arr: Vec<String> = serde_json::from_str(extract_json_array(text)).unwrap_or_default();
    Ok(arr)
}

fn default_model(provider_id: &str) -> String {
    match provider_id {
        "openai" => "gpt-4o-mini".into(),
        "anthropic" => "claude-3-5-haiku-20241022".into(),
        "ollama" => "llama3".into(),
        _ => "default".into(),
    }
}

fn extract_json_array(s: &str) -> &str {
    if let (Some(a), Some(b)) = (s.find('['), s.rfind(']')) {
        return &s[a..=b];
    }
    s
}
