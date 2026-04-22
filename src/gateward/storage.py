"""SQLite audit log for Gateward.

One row per intercepted JSON-RPC message, plus a session row per run. WAL mode
is enabled so readers (``gateward tail --follow``) never block writers.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

SCHEMA_SQL = """
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
"""

# Messages over this size get truncated with a marker so a single huge blob
# cannot bloat the audit DB. The real message still flows through the proxy
# unmodified — truncation only affects what is stored.
MAX_LOGGED_BYTES = 1024 * 1024


def default_db_path() -> Path:
    override = os.environ.get("GATEWARD_DB_PATH")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".gateward" / "audit.db"


class Storage:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            isolation_level=None,  # autocommit
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.executescript(SCHEMA_SQL)

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass

    def log_message(
        self,
        session_id: str,
        direction: str,
        message: dict[str, Any],
        method: str | None,
        tool_name: str | None,
        decision: str,
        reason: str,
        server_name: str,
    ) -> None:
        serialized = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
        if len(serialized) > MAX_LOGGED_BYTES:
            serialized = serialized[:MAX_LOGGED_BYTES] + "...[truncated]"
        self._conn.execute(
            """
            INSERT INTO messages (
                session_id, timestamp_ns, direction, message_json,
                method, tool_name, decision, decision_reason, server_name
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                time.time_ns(),
                direction,
                serialized,
                method,
                tool_name,
                decision,
                reason or None,
                server_name,
            ),
        )

    def start_session(self, session_id: str, server_name: str, server_command: str) -> None:
        self._conn.execute(
            """
            INSERT INTO sessions (session_id, started_at_ns, server_name, server_command)
            VALUES (?, ?, ?, ?)
            """,
            (session_id, time.time_ns(), server_name, server_command),
        )

    def end_session(self, session_id: str) -> None:
        self._conn.execute(
            "UPDATE sessions SET ended_at_ns = ? WHERE session_id = ? AND ended_at_ns IS NULL",
            (time.time_ns(), session_id),
        )

    def tail(self, last_id: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        cursor = self._conn.execute(
            """
            SELECT id, session_id, timestamp_ns, direction, message_json,
                   method, tool_name, decision, decision_reason, server_name
            FROM messages
            WHERE id > ?
            ORDER BY id ASC
            LIMIT ?
            """,
            (last_id, limit),
        )
        return [dict(row) for row in cursor.fetchall()]
