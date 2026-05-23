CREATE TABLE IF NOT EXISTS websocket_messages (
    id TEXT PRIMARY KEY,
    captured_at TEXT NOT NULL,
    host TEXT NOT NULL,
    url TEXT NOT NULL,
    direction TEXT NOT NULL,
    frame_type TEXT NOT NULL,
    payload BLOB NOT NULL,
    comment TEXT
);

CREATE INDEX IF NOT EXISTS idx_ws_host ON websocket_messages(host);
CREATE INDEX IF NOT EXISTS idx_ws_captured ON websocket_messages(captured_at);
