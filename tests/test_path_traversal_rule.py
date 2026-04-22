"""Tests for the path_traversal rule."""
from __future__ import annotations

from gateward.rules import check_path_traversal, evaluate
from gateward.session import Session


def _session() -> Session:
    return Session(server_name="server-filesystem", server_command="npx server-filesystem")


def _call(arguments: dict, id_: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": id_,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": arguments},
    }


def test_allows_normal_path():
    msg = _call({"path": "/tmp/workspace/file.txt"})
    assert check_path_traversal(msg, "client_to_server", _session()).action == "allow"


def test_blocks_traversal():
    msg = _call({"path": "../../../etc/passwd"})
    decision = check_path_traversal(msg, "client_to_server", _session())
    assert decision.action == "block"
    assert "path_traversal" in decision.reason


def test_blocks_etc_passwd():
    msg = _call({"path": "/etc/passwd"})
    assert check_path_traversal(msg, "client_to_server", _session()).action == "block"


def test_blocks_ssh_key():
    msg = _call({"path": "~/.ssh/id_rsa"})
    assert check_path_traversal(msg, "client_to_server", _session()).action == "block"


def test_blocks_aws_creds():
    msg = _call({"path": "~/.aws/credentials"})
    assert check_path_traversal(msg, "client_to_server", _session()).action == "block"


def test_blocks_env_file():
    msg = _call({"path": "/app/.env"})
    assert check_path_traversal(msg, "client_to_server", _session()).action == "block"


def test_blocks_url_encoded_traversal():
    msg = _call({"path": "..%2F..%2F..%2Fetc/passwd"})
    assert check_path_traversal(msg, "client_to_server", _session()).action == "block"


def test_allows_normal_relative():
    msg = _call({"path": "./src/main.py"})
    assert check_path_traversal(msg, "client_to_server", _session()).action == "allow"


def test_blocks_proc_environ():
    msg = _call({"path": "/proc/self/environ"})
    assert check_path_traversal(msg, "client_to_server", _session()).action == "block"


def test_blocks_in_nested_argument():
    msg = _call({"files": [{"path": "../../etc/shadow"}]})
    assert check_path_traversal(msg, "client_to_server", _session()).action == "block"


def test_ignored_on_server_direction():
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [{"type": "text", "text": "/etc/passwd contents"}]},
    }
    assert check_path_traversal(msg, "server_to_client", _session()).action == "allow"


def test_evaluate_blocks_path_traversal():
    decision = evaluate(_call({"path": "../../../etc/passwd"}), "client_to_server", _session())
    assert decision.action == "block"
    assert decision.rule == "path_traversal"
