//! Live multi-tester collaboration.
//!
//! A lightweight event stream that lets multiple Lancer instances share a
//! project. Each peer holds the same monotonic clock; the server (or a leader
//! peer) broadcasts CollabEvents to every member.
//!
//! Conflict resolution is last-writer-wins keyed by a UUID per logical object
//! (a history row, a repeater tab, etc.). Cursor / selection sync is a separate
//! per-peer presence channel.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub id: Uuid,
    pub display_name: String,
    pub color: String,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectKind {
    HistoryRow,
    RepeaterTab,
    IntruderAttack,
    Issue,
    ScopeRule,
    Macro,
    Bambda,
    OrganizerEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CollabEvent {
    PeerJoined(Peer),
    PeerLeft { id: Uuid },
    ObjectCreated { kind: ObjectKind, id: Uuid, body: serde_json::Value, author: Uuid, ts: DateTime<Utc> },
    ObjectUpdated { kind: ObjectKind, id: Uuid, body: serde_json::Value, author: Uuid, ts: DateTime<Utc> },
    ObjectDeleted { kind: ObjectKind, id: Uuid, author: Uuid, ts: DateTime<Utc> },
    CursorMoved { author: Uuid, surface: String, position: serde_json::Value, ts: DateTime<Utc> },
    SelectionChanged { author: Uuid, surface: String, range: serde_json::Value, ts: DateTime<Utc> },
    Chat { author: Uuid, message: String, ts: DateTime<Utc> },
}

#[derive(Clone)]
pub struct CollabHub {
    inner: Arc<RwLock<HubState>>,
    bus: broadcast::Sender<CollabEvent>,
}

struct HubState {
    peers: Vec<Peer>,
    log: Vec<CollabEvent>,
}

impl CollabHub {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            inner: Arc::new(RwLock::new(HubState { peers: Vec::new(), log: Vec::new() })),
            bus: tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<CollabEvent> {
        self.bus.subscribe()
    }

    pub fn peers(&self) -> Vec<Peer> {
        self.inner.read().peers.clone()
    }

    pub fn publish(&self, ev: CollabEvent) {
        match &ev {
            CollabEvent::PeerJoined(p) => self.inner.write().peers.push(p.clone()),
            CollabEvent::PeerLeft { id } => self.inner.write().peers.retain(|p| p.id != *id),
            _ => {}
        }
        self.inner.write().log.push(ev.clone());
        let _ = self.bus.send(ev);
    }

    /// Replay history for a late-joiner. Limits to the last N events.
    pub fn replay(&self, n: usize) -> Vec<CollabEvent> {
        let state = self.inner.read();
        let start = state.log.len().saturating_sub(n);
        state.log[start..].to_vec()
    }
}

impl Default for CollabHub {
    fn default() -> Self { Self::new() }
}
