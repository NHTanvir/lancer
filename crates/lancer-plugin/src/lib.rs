//! Plugin SDK + command palette.
//!
//! The plugin model is intentionally minimal in this commit: Lancer accepts
//! Rust-cdylib plugins discovered at a directory load path, plus in-app Rhai
//! scripts via `lancer_script`. A WASM runtime is planned for a later
//! release.

pub mod manifest;
pub mod palette;
pub mod registry;

pub use manifest::PluginManifest;
pub use palette::{Command, CommandPalette, CommandSource};
pub use registry::{PluginRegistry, LoadedPlugin};
