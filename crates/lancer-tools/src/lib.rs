//! Manual testing tools (Phase 2/3).
//!
//! - `repeater`: send modified requests, render response, history per tab
//! - `decoder`: encode/decode/hash pipeline (delegates to `lancer-core::transform`)
//! - `comparer`: word + byte diff engine
//! - `sequencer`: token-randomness statistical analysis
//! - `intruder`: payload-driven fuzzing (Sniper, Battering Ram, Pitchfork, Cluster Bomb)
//! - `client`: shared async HTTP client used by these tools

pub mod client;
pub mod comparer;
pub mod decoder;
pub mod intruder;
pub mod logger;
pub mod organizer_tools;
pub mod repeater;
pub mod sequencer;
pub mod engagement;

pub use client::HttpClient;
pub use comparer::{Comparer, DiffMode};
pub use decoder::Decoder;
pub use intruder::{Intruder, AttackKind, IntruderConfig, PayloadSet, PayloadProcessor};
pub use repeater::{Repeater, RepeaterTab};
pub use sequencer::{Sequencer, SequencerReport};
