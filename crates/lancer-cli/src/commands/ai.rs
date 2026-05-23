//! `lancer ai` — send a prompt to the configured BYO-LLM provider.

use std::io::Read;

use anyhow::Result;
use clap::{Args, ValueEnum};
use lancer_ai::{Anthropic, LlmMessage, LlmProvider, LlmRequest, Ollama, OpenAi};

#[derive(Debug, Args)]
pub struct AiArgs {
    /// Prompt text. Use `-` to read from stdin.
    prompt: String,
    #[arg(long, value_enum, default_value_t = Provider::Ollama)]
    provider: Provider,
    #[arg(long, default_value = "")]
    model: String,
    #[arg(long, env = "LANCER_AI_KEY", default_value = "")]
    api_key: String,
    #[arg(long)]
    system: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Provider {
    OpenAi,
    Anthropic,
    Ollama,
}

pub async fn run(args: AiArgs) -> Result<()> {
    let prompt = if args.prompt == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s
    } else {
        args.prompt.clone()
    };
    let mut req = LlmRequest::default();
    req.model = if args.model.is_empty() {
        match args.provider {
            Provider::OpenAi => "gpt-4o-mini".into(),
            Provider::Anthropic => "claude-3-5-haiku-20241022".into(),
            Provider::Ollama => "llama3".into(),
        }
    } else {
        args.model
    };
    req.messages = vec![LlmMessage { role: "user".into(), content: prompt }];
    req.system = args.system;
    req.max_tokens = Some(1024);

    let provider: Box<dyn LlmProvider> = match args.provider {
        Provider::OpenAi => Box::new(OpenAi { api_key: args.api_key, ..Default::default() }),
        Provider::Anthropic => Box::new(Anthropic { api_key: args.api_key, ..Default::default() }),
        Provider::Ollama => Box::new(Ollama::default()),
    };
    let resp = provider.complete(&req).await?;
    println!("{}", resp.content);
    Ok(())
}
