CREATE TABLE IF NOT EXISTS project_meta (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    scope_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS history (
    id TEXT PRIMARY KEY,
    captured_at TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    scheme TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER,
    response_length INTEGER,
    mime TEXT,
    tool_generated INTEGER NOT NULL DEFAULT 0,
    color TEXT,
    comment TEXT,
    in_scope INTEGER NOT NULL DEFAULT 0,
    request_blob BLOB NOT NULL,
    response_blob BLOB,
    elapsed_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_history_host ON history(host);
CREATE INDEX IF NOT EXISTS idx_history_status ON history(status);
CREATE INDEX IF NOT EXISTS idx_history_captured ON history(captured_at);
CREATE INDEX IF NOT EXISTS idx_history_method ON history(method);

CREATE TABLE IF NOT EXISTS match_replace_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    match_pattern TEXT NOT NULL,
    replace_with TEXT NOT NULL,
    is_regex INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    only_in_scope INTEGER NOT NULL DEFAULT 0,
    sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS config_library (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    body_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(kind, name)
);

CREATE TABLE IF NOT EXISTS macros (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    steps_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cookie_jar (
    domain TEXT NOT NULL,
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    expires TEXT,
    secure INTEGER NOT NULL DEFAULT 0,
    http_only INTEGER NOT NULL DEFAULT 0,
    same_site TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY(domain, path, name)
);
