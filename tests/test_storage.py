"""Storage tests: schema creation, writes, tail ordering and pagination."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from gateward.storage import MAX_LOGGED_BYTES, Storage


def test_schema_created(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "audit.db")
    try:
        cur = storage._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [r[0] for r in cur.fetchall()]
        assert "messages" in tables
        assert "sessions" in tables
        mode = storage._conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"
    finally:
        storage.close()


def test_log_and_tail_ordered(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "audit.db")
    try:
        storage.start_session("s1", "srv", "cmd")
        for i in range(1000):
            storage.log_message(
                "s1",
                "client_to_server" if i % 2 == 0 else "server_to_client",
                {"i": i},
                "tools/call" if i % 2 == 0 else None,
                "t" if i % 2 == 0 else None,
                "allow",
                "",
                "srv",
            )
        rows = []
        last_id = 0
        while True:
            page = storage.tail(last_id=last_id, limit=128)
            if not page:
                break
            rows.extend(page)
            last_id = page[-1]["id"]

        assert len(rows) == 1000
        assert [r["id"] for r in rows] == sorted(r["id"] for r in rows)
        assert json.loads(rows[0]["message_json"]) == {"i": 0}
        assert json.loads(rows[999]["message_json"]) == {"i": 999}
    finally:
        storage.close()


def test_end_session_sets_timestamp(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "audit.db")
    try:
        storage.start_session("s1", "srv", "cmd")
        storage.end_session("s1")
        row = storage._conn.execute(
            "SELECT started_at_ns, ended_at_ns FROM sessions WHERE session_id='s1'"
        ).fetchone()
        assert row["started_at_ns"] > 0
        assert row["ended_at_ns"] is not None
        assert row["ended_at_ns"] >= row["started_at_ns"]
    finally:
        storage.close()


def test_large_message_truncated(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "audit.db")
    try:
        storage.start_session("s1", "srv", "cmd")
        big = {"data": "x" * (2 * MAX_LOGGED_BYTES)}
        storage.log_message("s1", "client_to_server", big, None, None, "allow", "", "srv")
        row = storage.tail()[0]
        assert row["message_json"].endswith("...[truncated]")
        assert len(row["message_json"]) <= MAX_LOGGED_BYTES + len("...[truncated]")
    finally:
        storage.close()


def test_decision_check_constraint(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "audit.db")
    try:
        storage.start_session("s1", "srv", "cmd")
        # invalid decision value should raise IntegrityError
        try:
            storage._conn.execute(
                "INSERT INTO messages(session_id, timestamp_ns, direction, message_json, decision, server_name) "
                "VALUES ('s1', 1, 'client_to_server', '{}', 'nope', 'srv')"
            )
            raised = False
        except sqlite3.IntegrityError:
            raised = True
        assert raised
    finally:
        storage.close()
