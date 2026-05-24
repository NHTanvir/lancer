//! Blocking intercept queue.
//!
//! When the intercept engine decides to pause a request, the proxy pipeline
//! calls `InterceptPauseQueue::pause()` which blocks until the UI either
//! forwards (optionally with edits) or drops the request.

use std::collections::VecDeque;
use std::sync::Arc;

use lancer_core::HttpRequest;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PausedRequest {
    pub id: Uuid,
    pub request: HttpRequest,
    /// Wire-format string for display / editing in the UI.
    pub wire: String,
}

pub enum InterceptResolution {
    Forward(HttpRequest),
    Drop,
}

struct PendingItem {
    id: Uuid,
    request: HttpRequest,
    tx: oneshot::Sender<InterceptResolution>,
}

#[derive(Default)]
pub struct InterceptPauseQueue {
    pending: Mutex<VecDeque<PendingItem>>,
}

impl std::fmt::Debug for InterceptPauseQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InterceptPauseQueue {{ len: {} }}", self.pending.lock().len())
    }
}

impl InterceptPauseQueue {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Called by the proxy — blocks the connection until the UI resolves it.
    pub async fn pause(&self, req: HttpRequest) -> InterceptResolution {
        let (tx, rx) = oneshot::channel();
        let id = req.meta.id;
        let fallback = req.clone();
        self.pending.lock().push_back(PendingItem { id, request: req, tx });
        rx.await.unwrap_or(InterceptResolution::Forward(fallback))
    }

    /// Returns the list of currently paused requests (for API polling).
    pub fn list(&self) -> Vec<PausedRequest> {
        self.pending
            .lock()
            .iter()
            .map(|item| {
                let wire = String::from_utf8_lossy(&item.request.to_wire()).into_owned();
                PausedRequest { id: item.id, request: item.request.clone(), wire }
            })
            .collect()
    }

    /// Resolve a specific paused request. Returns false if ID not found.
    pub fn resolve(&self, id: Uuid, resolution: InterceptResolution) -> bool {
        let mut pending = self.pending.lock();
        if let Some(pos) = pending.iter().position(|item| item.id == id) {
            let item = pending.remove(pos).unwrap();
            let _ = item.tx.send(resolution);
            true
        } else {
            false
        }
    }

    pub fn len(&self) -> usize {
        self.pending.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.lock().is_empty()
    }
}
