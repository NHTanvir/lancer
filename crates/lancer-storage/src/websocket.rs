//! WebSocket message history.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WsDirection {
    ClientToServer,
    ServerToClient,
}

impl WsDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            WsDirection::ClientToServer => "c2s",
            WsDirection::ServerToClient => "s2c",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WsFrameType {
    Text,
    Binary,
    Ping,
    Pong,
    Close,
}

impl WsFrameType {
    pub fn as_str(self) -> &'static str {
        match self {
            WsFrameType::Text => "text",
            WsFrameType::Binary => "binary",
            WsFrameType::Ping => "ping",
            WsFrameType::Pong => "pong",
            WsFrameType::Close => "close",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessage {
    pub id: Uuid,
    pub captured_at: DateTime<Utc>,
    pub host: String,
    pub url: String,
    pub direction: WsDirection,
    pub frame_type: WsFrameType,
    pub payload: Vec<u8>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WsStore {
    pool: SqlitePool,
}

impl WsStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, msg: &WsMessage) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO websocket_messages(id, captured_at, host, url, direction, frame_type, payload, comment)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(msg.id.to_string())
        .bind(msg.captured_at)
        .bind(&msg.host)
        .bind(&msg.url)
        .bind(msg.direction.as_str())
        .bind(msg.frame_type.as_str())
        .bind(&msg.payload)
        .bind(&msg.comment)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list(&self, host: Option<&str>) -> anyhow::Result<Vec<WsMessage>> {
        let rows = match host {
            Some(h) => {
                sqlx::query(
                    "SELECT * FROM websocket_messages WHERE host = ? ORDER BY captured_at DESC",
                )
                .bind(h)
                .fetch_all(&self.pool)
                .await?
            }
            None => sqlx::query("SELECT * FROM websocket_messages ORDER BY captured_at DESC")
                .fetch_all(&self.pool)
                .await?,
        };
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let id_str: String = r.try_get("id")?;
            let dir_str: String = r.try_get("direction")?;
            let frame_str: String = r.try_get("frame_type")?;
            out.push(WsMessage {
                id: Uuid::parse_str(&id_str)?,
                captured_at: r.try_get("captured_at")?,
                host: r.try_get("host")?,
                url: r.try_get("url")?,
                direction: match dir_str.as_str() {
                    "c2s" => WsDirection::ClientToServer,
                    _ => WsDirection::ServerToClient,
                },
                frame_type: match frame_str.as_str() {
                    "text" => WsFrameType::Text,
                    "binary" => WsFrameType::Binary,
                    "ping" => WsFrameType::Ping,
                    "pong" => WsFrameType::Pong,
                    _ => WsFrameType::Close,
                },
                payload: r.try_get("payload")?,
                comment: r.try_get("comment")?,
            });
        }
        Ok(out)
    }
}
