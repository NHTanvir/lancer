//! Scanner — passive observation + active checks.
//!
//! The scanner is structured around two traits:
//! - `PassiveCheck` — sees a finished request/response pair, never sends
//! - `ActiveCheck` — has access to an `HttpClient` and may send extra requests
//!
//! Checks register themselves with the `ScanEngine`, which orchestrates
//! crawling, insertion-point detection, throttling, and result collection.

pub mod active;
pub mod collaborator;
pub mod config;
pub mod engine;
pub mod insertion;
pub mod passive;

use async_trait::async_trait;
use lancer_core::{HttpRequest, HttpResponse};
use lancer_storage::issues::Issue;
use lancer_tools::HttpClient;

pub use config::{ScanConfig, ScanPreset};
pub use engine::ScanEngine;
pub use insertion::{InsertionPoint, find_insertion_points};

#[async_trait]
pub trait PassiveCheck: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    async fn check(&self, request: &HttpRequest, response: &HttpResponse) -> Vec<Issue>;
}

#[async_trait]
pub trait ActiveCheck: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    async fn run(&self, client: &HttpClient, base: &HttpRequest, point: &InsertionPoint) -> Vec<Issue>;
}
