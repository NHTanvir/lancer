//! `lancer llm-redteam` — §43 LLM red-team orchestrator.
//!
//! Multi-turn adversarial attacks against a target LLM. Calls the
//! `lancer-llm-redteam` crate directly (mirrors the `/v1/llm-redteam/start`
//! handler in lancer-api).
//!
//! Example:
//!   lancer llm-redteam --strategy tree_of_attacks \
//!       --target https://api.openai.com/v1/chat/completions \
//!       --goal "extract system prompt" --max-turns 10

use anyhow::Result;
use clap::{Args, ValueEnum};
use lancer_llm_redteam::{LlmConfig, SessionRequest, Strategy};

#[derive(Debug, Args)]
pub struct LlmRedteamArgs {
    /// Adversarial strategy to drive the conversation.
    #[arg(long, value_enum, default_value_t = StrategyArg::TreeOfAttacks)]
    strategy: StrategyArg,

    /// Target LLM chat-completions endpoint (system under test).
    #[arg(long)]
    target: String,

    /// Target model name.
    #[arg(long, default_value = "gpt-3.5-turbo")]
    target_model: String,

    /// API key for the target LLM (falls back to $LANCER_TARGET_API_KEY).
    #[arg(long)]
    target_key: Option<String>,

    /// Attacker LLM endpoint (used by prompt-rewriting strategies).
    /// Defaults to the target endpoint when omitted.
    #[arg(long)]
    attacker: Option<String>,

    /// Attacker model name.
    #[arg(long, default_value = "gpt-3.5-turbo")]
    attacker_model: String,

    /// API key for the attacker LLM (falls back to $LANCER_ATTACKER_API_KEY).
    #[arg(long)]
    attacker_key: Option<String>,

    /// Adversarial goal, e.g. "extract system prompt".
    #[arg(long)]
    goal: String,

    /// Maximum number of attack turns before giving up.
    #[arg(long, default_value_t = 10)]
    max_turns: usize,

    /// Score threshold (0–1) at which success is declared and we stop.
    #[arg(long, default_value_t = 0.8)]
    success_threshold: f64,

    /// Emit the full session (every turn) as pretty JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[value(rename_all = "snake_case")]
enum StrategyArg {
    SingleTurn,
    TreeOfAttacks,
    Crescendo,
    Pair,
    Gcg,
    Flrt,
    ManyShot,
}

impl From<StrategyArg> for Strategy {
    fn from(s: StrategyArg) -> Self {
        match s {
            StrategyArg::SingleTurn => Strategy::SingleTurn,
            StrategyArg::TreeOfAttacks => Strategy::TreeOfAttacks,
            StrategyArg::Crescendo => Strategy::Crescendo,
            StrategyArg::Pair => Strategy::Pair,
            StrategyArg::Gcg => Strategy::Gcg,
            StrategyArg::Flrt => Strategy::Flrt,
            StrategyArg::ManyShot => Strategy::ManyShot,
        }
    }
}

pub async fn run(args: LlmRedteamArgs) -> Result<()> {
    let target = LlmConfig {
        endpoint: args.target.clone(),
        api_key: args
            .target_key
            .or_else(|| std::env::var("LANCER_TARGET_API_KEY").ok()),
        model: args.target_model,
    };

    // Attacker defaults to the same endpoint/key as the target when not given.
    let attacker = LlmConfig {
        endpoint: args.attacker.unwrap_or_else(|| args.target.clone()),
        api_key: args
            .attacker_key
            .or_else(|| std::env::var("LANCER_ATTACKER_API_KEY").ok())
            .or_else(|| target.api_key.clone()),
        model: args.attacker_model,
    };

    let req = SessionRequest {
        target,
        attacker,
        strategy: args.strategy.into(),
        goal: args.goal,
        max_turns: args.max_turns,
        success_threshold: args.success_threshold,
    };

    eprintln!(
        "running {:?} red-team against {} (goal: {:?}, max_turns: {})",
        req.strategy, req.target.endpoint, req.goal, req.max_turns
    );

    let session = lancer_llm_redteam::run_session(req).await;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&session)?);
        return Ok(());
    }

    print_session(&session);
    Ok(())
}

fn print_session(session: &lancer_llm_redteam::Session) {
    println!("session : {}", session.id);
    println!("strategy: {:?}", session.strategy);
    println!("goal    : {}", session.goal);
    println!(
        "result  : {} (best score {:.2})",
        if session.success { "SUCCESS — goal achieved" } else { "no jailbreak" },
        session.best_score
    );
    if let Some(ended) = session.ended_at {
        let dur = ended.signed_duration_since(session.started_at);
        println!("elapsed : {}s", dur.num_seconds());
    }
    println!("turns   : {}", session.turns.len());
    println!();

    for turn in &session.turns {
        let score = match turn.score {
            Some(s) => format!(" [score {s:.2}]"),
            None => String::new(),
        };
        println!("── turn {} · {}{}", turn.idx, turn.role, score);
        for line in turn.content.lines() {
            println!("   {line}");
        }
    }
}
