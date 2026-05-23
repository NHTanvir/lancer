//! Scanner. Phase 1 only seeds the trait. Phase 4 lands the real checks.

use anyhow::Result;
use async_trait::async_trait;
use lancer_core::{HttpRequest, HttpResponse};
use lancer_storage::issues::Issue;

pub mod active;
pub mod passive;

/// Common trait for any check that observes a request/response pair without
/// generating new traffic.
#[async_trait]
pub trait PassiveCheck: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    async fn check(&self, request: &HttpRequest, response: &HttpResponse) -> Vec<Issue>;
}

/// Common trait for any check that needs to send additional requests.
#[async_trait]
pub trait ActiveCheck: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    async fn run(&self, base: &HttpRequest) -> Result<Vec<Issue>>;
}
