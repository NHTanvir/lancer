//! Event bus used by the proxy to broadcast captured traffic to the rest of
//! Lancer (storage layer, GUI, extensions).

use lancer_core::{HttpRequest, HttpResponse, MessageId};
use tokio::sync::mpsc;

/// Things the proxy may emit at runtime.
#[derive(Debug, Clone)]
pub enum ProxyEvent {
    RequestCaptured {
        id: MessageId,
        request: HttpRequest,
        in_scope: bool,
    },
    ResponseCaptured {
        id: MessageId,
        response: HttpResponse,
    },
    ConnectionOpened {
        host: String,
        port: u16,
        tls: bool,
    },
    ConnectionClosed {
        host: String,
        port: u16,
    },
    InterceptionPaused {
        id: MessageId,
    },
    Error {
        message: String,
    },
}

/// Thin wrapper around an mpsc sender for fan-out via the listener.
#[derive(Debug, Clone)]
pub struct ProxyEventSink {
    tx: mpsc::Sender<ProxyEvent>,
}

impl ProxyEventSink {
    pub fn new(capacity: usize) -> (Self, mpsc::Receiver<ProxyEvent>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { tx }, rx)
    }

    pub async fn emit(&self, ev: ProxyEvent) {
        let _ = self.tx.send(ev).await;
    }

    pub fn try_emit(&self, ev: ProxyEvent) {
        let _ = self.tx.try_send(ev);
    }
}
