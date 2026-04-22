-- Reference copy of the SQLite schema. The authoritative version is
-- embedded as SCHEMA_SQL in storage.py and executed at first run.
-- Edits here are documentation only; update storage.py as well.

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp_ns INTEGER NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('client_to_server', 'server_to_client')),
    message_json TEXT NOT NULL,
    method TEXT,
    tool_name TEXT,
    decision TEXT NOT NULL CHECK(decision IN ('allow', 'block', 'warn')),
    decision_reason TEXT,
    server_name TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_messages_decision ON messages(decision);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    started_at_ns INTEGER NOT NULL,
    ended_at_ns INTEGER,
    server_name TEXT NOT NULL,
    server_command TEXT NOT NULL
);
