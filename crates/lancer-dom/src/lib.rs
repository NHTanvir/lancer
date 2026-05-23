//! DOM Invader equivalent.
//!
//! This is *static* analysis over captured JavaScript bodies — Lancer doesn't
//! run a headless Chromium yet, so we approximate Burp's DOM Invader by
//! grepping for known DOM sources and sinks, flagging direct flows, logging
//! postMessage senders/receivers, and matching common prototype-pollution
//! gadgets and DOM-clobbering markers.

pub mod clobbering;
pub mod message;
pub mod proto_gadgets;
pub mod sinks;

pub use clobbering::{detect_clobbering, ClobberHit};
pub use message::{find_message_endpoints, PostMessageEndpoint};
pub use proto_gadgets::{find_gadgets, GadgetHit};
pub use sinks::{analyze_js, DomFinding, DomSink, DomSource};
