//! Mobile-testing helpers.
//!
//! Three pieces:
//! - `android`: ADB-driven CA push + user proxy setup
//! - `ios`: instructions emitter (real install requires user interaction)
//! - `frida`: ready-to-go SSL-pinning bypass snippets for common pinners

pub mod android;
pub mod frida;
pub mod ios;
