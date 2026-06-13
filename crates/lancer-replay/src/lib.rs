//! Access-control / IDOR / business-logic testing suite.
//!
//! Four cohesive modules that share a live HTTP-replay workflow:
//!
//! - [`dual_session`] — replay one request under two session identities and
//!   compare the responses (broken-access-control / IDOR detector).
//! - [`id_mutate`] — detect ID-like values in a captured request, mutate them,
//!   replay each, and flag mutations that reach another object.
//! - [`resp_diff`] — structured response differ (status / headers / body
//!   similarity) for side-by-side comparison.
//! - [`flow_graph`] — build a navigation graph from the proxy request log.

pub mod dual_session;
pub mod flow_graph;
pub mod id_mutate;
pub mod resp_diff;

pub use dual_session::{dual_replay, DualReplayResult, ReplayResp, SessionCreds};
pub use flow_graph::{build_flow_graph, FlowEdge, FlowEntry, FlowGraph, FlowNode};
pub use id_mutate::{fuzz_ids, IdFuzzReport, IdHit};
pub use resp_diff::{diff_responses, RespDiff};

/// Jaccard similarity over whitespace-split tokens (0.0–1.0). Shared by the
/// replay/diff modules to score "how alike" two response bodies are.
pub(crate) fn token_similarity(a: &str, b: &str) -> f64 {
    use std::collections::HashSet;
    let sa: HashSet<&str> = a.split_whitespace().collect();
    let sb: HashSet<&str> = b.split_whitespace().collect();
    if sa.is_empty() && sb.is_empty() {
        return 1.0;
    }
    let inter = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count() as f64;
    if union == 0.0 { 1.0 } else { inter / union }
}
