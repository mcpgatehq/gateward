"""End-to-end proxy tests: spawn gateward as a subprocess around a fake MCP server.

These tests exercise the full stdio transport path — parent stdin/stdout
wrapping, subprocess spawn, bidirectional forwarding, rule evaluation,
blocked-message error synthesis, and clean shutdown on EOF or crash.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from pathlib import Path

import pytest

FAKE_SERVER = Path(__file__).parent / "fake_mcp_server.py"


async def _spawn_proxy(db_path: Path) -> asyncio.subprocess.Process:
    env = {
        **os.environ,
        "GATEWARD_DB_PATH": str(db_path),
        "GATEWARD_SCHEMA_DB_PATH": str(db_path.parent / "schema.db"),
    }
    return await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "gateward",
        "run",
        "--",
        sys.executable,
        str(FAKE_SERVER),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )


async def _send(proc: asyncio.subprocess.Process, msg: dict) -> None:
    assert proc.stdin is not None
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    await proc.stdin.drain()


async def _recv(proc: asyncio.subprocess.Process, timeout: float = 5.0) -> dict:
    assert proc.stdout is not None
    line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
    assert line, "proxy closed stdout before sending a response"
    return json.loads(line.decode())


async def _shutdown(proc: asyncio.subprocess.Process) -> int:
    if proc.stdin and not proc.stdin.is_closing():
        try:
            proc.stdin.close()
        except Exception:
            pass
    try:
        return await asyncio.wait_for(proc.wait(), timeout=5.0)
    except asyncio.TimeoutError:
        proc.terminate()
        try:
            return await asyncio.wait_for(proc.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            proc.kill()
            return await proc.wait()


def _read_db(db_path: Path):
    import sqlite3

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        messages = [dict(r) for r in conn.execute("SELECT * FROM messages ORDER BY id").fetchall()]
        sessions = [dict(r) for r in conn.execute("SELECT * FROM sessions").fetchall()]
    finally:
        conn.close()
    return messages, sessions


# --------- Test scenarios ---------


def test_happy_path_initialize_and_tool_call(tmp_path: Path) -> None:
    async def _run():
        db = tmp_path / "audit.db"
        proc = await _spawn_proxy(db)
        try:
            await _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            init_resp = await _recv(proc)
            assert init_resp["id"] == 1
            assert "result" in init_resp

            await _send(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "echo", "arguments": {"text": "hello"}},
                },
            )
            echo_resp = await _recv(proc)
            assert echo_resp["id"] == 2
            # Rule 12 appends a canary marker to every forwarded response;
            # assert the user-visible prefix is intact, not exact equality.
            assert echo_resp["result"]["content"][0]["text"].startswith("hello")
            assert "<!-- gw:" in echo_resp["result"]["content"][0]["text"]
        finally:
            await _shutdown(proc)

        messages, sessions = _read_db(db)
        assert len(sessions) == 1
        assert sessions[0]["ended_at_ns"] is not None

        decisions = [m["decision"] for m in messages]
        assert all(d == "allow" for d in decisions), decisions
        methods = [m["method"] for m in messages if m["method"]]
        assert "initialize" in methods
        assert "tools/call" in methods

    asyncio.run(_run())


def test_injection_phrase_in_server_response_is_blocked(tmp_path: Path) -> None:
    async def _run():
        db = tmp_path / "audit.db"
        proc = await _spawn_proxy(db)
        try:
            await _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            await _recv(proc)

            await _send(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 42,
                    "method": "tools/call",
                    "params": {"name": "inject_test", "arguments": {}},
                },
            )
            resp = await _recv(proc)
            assert resp["id"] == 42
            assert "error" in resp
            assert resp["error"]["code"] == -32000
            assert "injection_phrase" in resp["error"]["message"]
            # Must NOT leak the matched phrase to the client
            assert "IGNORE" not in resp["error"]["message"]
        finally:
            await _shutdown(proc)

        messages, _ = _read_db(db)
        blocks = [m for m in messages if m["decision"] == "block"]
        assert len(blocks) == 1
        assert blocks[0]["direction"] == "server_to_client"
        assert "injection_phrase_detected" in blocks[0]["decision_reason"]

    asyncio.run(_run())


def test_cross_repo_block_on_second_call(tmp_path: Path) -> None:
    async def _run():
        db = tmp_path / "audit.db"
        # Rename fake server path so the proxy's server_name contains "github"
        # to activate the cross-repo rule.
        target_dir = tmp_path / "github-fake"
        target_dir.mkdir()
        server_copy = target_dir / "server-github.py"
        server_copy.write_text(FAKE_SERVER.read_text())

        env = {
            **os.environ,
            "GATEWARD_DB_PATH": str(db),
            "GATEWARD_SCHEMA_DB_PATH": str(db.parent / "schema.db"),
        }
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "gateward",
            "run",
            "--",
            sys.executable,
            str(server_copy),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            await _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            await _recv(proc)

            await _send(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "list_issues",
                        "arguments": {"owner": "alice", "repo": "projectA"},
                    },
                },
            )
            first = await _recv(proc)
            assert first["id"] == 2
            assert "result" in first

            await _send(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "list_issues",
                        "arguments": {"owner": "eve", "repo": "exfil"},
                    },
                },
            )
            second = await _recv(proc)
            assert second["id"] == 3
            assert "error" in second
            assert second["error"]["code"] == -32000
            assert "cross_repo" in second["error"]["message"]
        finally:
            await _shutdown(proc)

        messages, _ = _read_db(db)
        blocks = [m for m in messages if m["decision"] == "block"]
        assert len(blocks) == 1
        assert blocks[0]["direction"] == "client_to_server"
        assert "cross_repository_access" in blocks[0]["decision_reason"]

    asyncio.run(_run())


def test_destructive_shell_blocked(tmp_path: Path) -> None:
    async def _run():
        db = tmp_path / "audit.db"
        proc = await _spawn_proxy(db)
        try:
            await _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            await _recv(proc)
            await _send(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "echo", "arguments": {"text": "rm -rf /home/victim"}},
                },
            )
            resp = await _recv(proc)
            assert resp["id"] == 2
            assert "error" in resp
            assert resp["error"]["code"] == -32000
            assert "destructive_shell" in resp["error"]["message"]
        finally:
            await _shutdown(proc)

        messages, _ = _read_db(db)
        blocks = [m for m in messages if m["decision"] == "block"]
        assert len(blocks) == 1
        assert blocks[0]["direction"] == "client_to_server"
        assert "destructive_shell_command" in blocks[0]["decision_reason"]

    asyncio.run(_run())


def test_subprocess_crash_exits_cleanly(tmp_path: Path) -> None:
    async def _run():
        db = tmp_path / "audit.db"
        # Script that dies after receiving one message
        crash_script = tmp_path / "crash.py"
        crash_script.write_text(
            "import sys\n"
            "sys.stdin.readline()\n"
            "sys.exit(17)\n"
        )
        env = {
            **os.environ,
            "GATEWARD_DB_PATH": str(db),
            "GATEWARD_SCHEMA_DB_PATH": str(db.parent / "schema.db"),
        }
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "gateward",
            "run",
            "--",
            sys.executable,
            str(crash_script),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        await _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        rc = await _shutdown(proc)
        assert rc == 17

        _, sessions = _read_db(db)
        assert len(sessions) == 1
        assert sessions[0]["ended_at_ns"] is not None

    asyncio.run(_run())
