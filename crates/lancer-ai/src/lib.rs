//! BYO-LLM trait + thin HTTP clients for the major providers.
//!
//! Lancer never ships an embedded model and never talks to a remote provider
//! unless the user has explicitly configured one. The user supplies an
//! `LlmProvider` and Lancer just delegates.

#![allow(dead_code)]

pub mod payload_mutation;

use anyhow::Result;
use async_trait::async_trait;
use lancer_core::HttpRequest;
use lancer_tools::HttpClient;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmMessage {
    pub role: String, // "system" | "user" | "assistant"
    pub content: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LlmRequest {
    pub model: String,
    pub messages: Vec<LlmMessage>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub system: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    pub content: String,
    pub provider: String,
}

#[async_trait]
pub trait LlmProvider: Send + Sync {
    fn id(&self) -> &'static str;
    async fn complete(&self, req: &LlmRequest) -> Result<LlmResponse>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAi {
    pub base_url: String,
    pub api_key: String,
}

impl Default for OpenAi {
    fn default() -> Self {
        Self {
            base_url: "https://api.openai.com".to_string(),
            api_key: String::new(),
        }
    }
}

#[async_trait]
impl LlmProvider for OpenAi {
    fn id(&self) -> &'static str {
        "openai"
    }
    async fn complete(&self, req: &LlmRequest) -> Result<LlmResponse> {
        let body = serde_json::json!({
            "model": req.model,
            "messages": req.messages,
            "temperature": req.temperature,
            "max_tokens": req.max_tokens,
        });
        let mut hreq = HttpRequest::builder("POST", &format!("{}/v1/chat/completions", self.base_url))?;
        hreq.set_header("Content-Type", "application/json");
        hreq.set_header("Authorization", format!("Bearer {}", self.api_key));
        hreq.body = bytes::Bytes::from(serde_json::to_vec(&body)?);
        let resp = HttpClient::new().send(&hreq).await?;
        let v: serde_json::Value = serde_json::from_slice(&resp.body)?;
        let content = v["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        Ok(LlmResponse { content, provider: "openai".into() })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anthropic {
    pub base_url: String,
    pub api_key: String,
    pub version: String,
}

impl Default for Anthropic {
    fn default() -> Self {
        Self {
            base_url: "https://api.anthropic.com".to_string(),
            api_key: String::new(),
            version: "2023-06-01".to_string(),
        }
    }
}

#[async_trait]
impl LlmProvider for Anthropic {
    fn id(&self) -> &'static str {
        "anthropic"
    }
    async fn complete(&self, req: &LlmRequest) -> Result<LlmResponse> {
        let body = serde_json::json!({
            "model": req.model,
            "max_tokens": req.max_tokens.unwrap_or(1024),
            "system": req.system,
            "temperature": req.temperature,
            "messages": req.messages.iter().filter(|m| m.role != "system").collect::<Vec<_>>(),
        });
        let mut hreq = HttpRequest::builder("POST", &format!("{}/v1/messages", self.base_url))?;
        hreq.set_header("Content-Type", "application/json");
        hreq.set_header("x-api-key", &self.api_key);
        hreq.set_header("anthropic-version", &self.version);
        hreq.body = bytes::Bytes::from(serde_json::to_vec(&body)?);
        let resp = HttpClient::new().send(&hreq).await?;
        let v: serde_json::Value = serde_json::from_slice(&resp.body)?;
        let content = v["content"][0]["text"].as_str().unwrap_or("").to_string();
        Ok(LlmResponse { content, provider: "anthropic".into() })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ollama {
    pub base_url: String,
}

impl Default for Ollama {
    fn default() -> Self {
        Self { base_url: "http://127.0.0.1:11434".to_string() }
    }
}

#[async_trait]
impl LlmProvider for Ollama {
    fn id(&self) -> &'static str {
        "ollama"
    }
    async fn complete(&self, req: &LlmRequest) -> Result<LlmResponse> {
        let body = serde_json::json!({
            "model": req.model,
            "messages": req.messages,
            "stream": false,
        });
        let mut hreq = HttpRequest::builder("POST", &format!("{}/api/chat", self.base_url))?;
        hreq.set_header("Content-Type", "application/json");
        hreq.body = bytes::Bytes::from(serde_json::to_vec(&body)?);
        let resp = HttpClient::new().send(&hreq).await?;
        let v: serde_json::Value = serde_json::from_slice(&resp.body)?;
        let content = v["message"]["content"].as_str().unwrap_or("").to_string();
        Ok(LlmResponse { content, provider: "ollama".into() })
    }
}

/// Convenience canned prompts used by the Repeater "Explain"/"Investigate" buttons.
pub mod prompts {
    pub const EXPLAIN: &str = "You are a senior application-security tester. Explain in plain English what the following HTTP request does, what response it likely produces, and any obvious security concerns. Be concise.";
    pub const INVESTIGATE: &str = "Suggest follow-up tests for the following HTTP exchange. List concrete payloads and parameter manipulations a tester should try. Focus on injection, authorization, and business-logic flaws.";
    pub const VALIDATE: &str = "Given this HTTP request/response and the alleged vulnerability, decide whether it is exploitable. Output: a one-line verdict, then 3 bullet points of reasoning.";
    pub const REPORT: &str = "Write a concise vulnerability report section for the following finding. Include: Description, Impact, Reproduction Steps, Remediation.";
}
