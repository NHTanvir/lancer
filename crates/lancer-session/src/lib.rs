//! Session-handling pieces:
//!
//! - `CookieJar`: shared per-project cookie store
//! - `Macro`: multi-step recorded sequence (e.g., login flow)
//! - `SessionRule`: scope + ordered actions, applied to in-flight requests

pub mod cookie_jar;
pub mod macros;
pub mod rules;

pub use cookie_jar::{Cookie, CookieJar, SameSite};
pub use macros::{Macro, MacroRunner, MacroStep};
pub use rules::{SessionAction, SessionRule, SessionEngine};
