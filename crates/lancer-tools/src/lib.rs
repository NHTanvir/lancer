//! Manual testing tools (Phase 2/3).
//!
//! - `repeater`: send modified requests, render response, history per tab
//! - `decoder`: encode/decode/hash pipeline (delegates to `lancer-core::transform`)
//! - `comparer`: word + byte diff engine
//! - `sequencer`: token-randomness statistical analysis
//! - `intruder`: payload-driven fuzzing (Sniper, Battering Ram, Pitchfork, Cluster Bomb)
//! - `client`: shared async HTTP client used by these tools
//! - `positions`: payload-position parsing (§…§ markers)
//! - `grep`: result-table analysis (grep-match, grep-extract, grep-payloads)

pub mod client;
pub mod comparer;
pub mod decoder;
pub mod engagement;
pub mod grep;
pub mod intruder;
pub mod logger;
pub mod organizer_tools;
pub mod payload_processor;
pub mod positions;
pub mod repeater;
pub mod sequencer;

pub use client::HttpClient;
pub use comparer::{Comparer, DiffMode};
pub use decoder::Decoder;
pub use intruder::{AttackKind, AttackResult, Intruder, IntruderConfig, PayloadProcessor, PayloadSet};
pub use payload_processor::{apply_chain, BuiltinList};
pub use positions::{ParsedTemplate, Position, PositionSlot, DEFAULT_MARKER};
pub use repeater::{Repeater, RepeaterEntry, RepeaterTab};
pub use sequencer::{Sequencer, SequencerReport};
pub use grep::{GrepConfig, GrepExtract, GrepResult};
