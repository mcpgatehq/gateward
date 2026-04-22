"""Fingerprint store for tool definitions across sessions (Rule 7).

On first encounter of a ``(server_command, tool_name)`` pair, the tool's
description and input schema are hashed and recorded. On subsequent
sessions, the same tool is re-hashed and compared. A mismatch is a rug
pull signal: the description or schema changed without a visible version
bump on the user's side.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path


def default_schema_db_path() -> Path:
    override = os.environ.get("GATEWARD_SCHEMA_DB_PATH")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".gateward" / "schema.db"


class SchemaStore:
    def __init__(self, db_path: str | os.PathLike[str] | None = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else default_schema_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False, isolation_level=None)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tool_fingerprints (
                server_command TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                description_hash TEXT NOT NULL,
                schema_hash TEXT NOT NULL,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (server_command, tool_name)
            )
            """
        )

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]

    def check_and_store(self, server_cmd: str, tools: list[dict]) -> list[str]:
        drifts: list[str] = []
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name", "")
            desc = tool.get("description", "") or ""
            schema = json.dumps(tool.get("inputSchema", {}) or {}, sort_keys=True)
            desc_hash = self._hash(desc)
            schema_hash = self._hash(schema)

            row = self._conn.execute(
                "SELECT description_hash, schema_hash FROM tool_fingerprints "
                "WHERE server_command=? AND tool_name=?",
                (server_cmd, name),
            ).fetchone()

            if row is None:
                self._conn.execute(
                    "INSERT INTO tool_fingerprints (server_command, tool_name, "
                    "description_hash, schema_hash) VALUES (?, ?, ?, ?)",
                    (server_cmd, name, desc_hash, schema_hash),
                )
            else:
                if row[0] != desc_hash:
                    drifts.append(
                        f"tool '{name}' description changed (was {row[0]}, now {desc_hash})"
                    )
                if row[1] != schema_hash:
                    drifts.append(
                        f"tool '{name}' schema changed (was {row[1]}, now {schema_hash})"
                    )
        return drifts

    def all_fingerprints(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT server_command, tool_name, description_hash, schema_hash, first_seen "
            "FROM tool_fingerprints ORDER BY server_command, tool_name"
        ).fetchall()
        return [
            {
                "server_command": r[0],
                "tool_name": r[1],
                "description_hash": r[2],
                "schema_hash": r[3],
                "first_seen": r[4],
            }
            for r in rows
        ]

    def reset(self, server_cmd: str | None = None) -> int:
        if server_cmd:
            cur = self._conn.execute(
                "DELETE FROM tool_fingerprints WHERE server_command=?", (server_cmd,)
            )
        else:
            cur = self._conn.execute("DELETE FROM tool_fingerprints")
        return cur.rowcount or 0
