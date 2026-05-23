CREATE TABLE IF NOT EXISTS issues (
    id TEXT PRIMARY KEY,
    found_at TEXT NOT NULL,
    host TEXT NOT NULL,
    url TEXT NOT NULL,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    description TEXT NOT NULL,
    remediation TEXT,
    evidence_request BLOB,
    evidence_response BLOB,
    history_id TEXT,
    check_id TEXT,
    false_positive INTEGER NOT NULL DEFAULT 0,
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_issues_host ON issues(host);
CREATE INDEX IF NOT EXISTS idx_issues_severity ON issues(severity);

CREATE TABLE IF NOT EXISTS organizer (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '',
    notes TEXT,
    request_blob BLOB NOT NULL,
    response_blob BLOB,
    added_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_organizer_tags ON organizer(tags);
