"""Tests for the secrets_in_response rule."""
from __future__ import annotations

from gateward.rules import check_secrets_in_response, evaluate
from gateward.session import Session


def _session() -> Session:
    return Session(server_name="server-filesystem", server_command="npx server-filesystem")


def _response(text: str, id_: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": id_,
        "result": {"content": [{"type": "text", "text": text}]},
    }


def test_allows_normal_response():
    msg = _response("Here are the contents of the file: hello world")
    assert check_secrets_in_response(msg, "server_to_client", _session()).action == "allow"


def test_blocks_openai_key():
    msg = _response("your key is sk-proj-abc123def456ghi789jkl012mno345pqr678")
    decision = check_secrets_in_response(msg, "server_to_client", _session())
    assert decision.action == "block"
    assert "secrets_in_response" in decision.reason


def test_blocks_github_pat():
    msg = _response("token=ghp_abcdefghijklmnopqrstuvwxyz0123456789AB")
    assert check_secrets_in_response(msg, "server_to_client", _session()).action == "block"


def test_blocks_aws_key():
    msg = _response("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
    assert check_secrets_in_response(msg, "server_to_client", _session()).action == "block"


def test_blocks_ssh_private_key():
    msg = _response(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    )
    assert check_secrets_in_response(msg, "server_to_client", _session()).action == "block"


def test_blocks_connection_string():
    msg = _response("DATABASE_URL=postgres://user:password@host:5432/db")
    assert check_secrets_in_response(msg, "server_to_client", _session()).action == "block"


def test_blocks_jwt():
    msg = _response(
        "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
    )
    assert check_secrets_in_response(msg, "server_to_client", _session()).action == "block"


def test_allows_short_strings():
    msg = _response("the prefix sk-short is too short to be a real key")
    assert check_secrets_in_response(msg, "server_to_client", _session()).action == "allow"


def test_blocks_bearer_token():
    msg = _response("Authorization header: Bearer eyJhbGciOiJIUzI1NiJ9abcdef012345")
    assert check_secrets_in_response(msg, "server_to_client", _session()).action == "block"


def test_ignored_on_client_direction():
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"text": "sk-proj-abc123def456ghi789jkl012mno"}},
    }
    assert check_secrets_in_response(msg, "client_to_server", _session()).action == "allow"


def test_evaluate_blocks_secrets_response():
    decision = evaluate(
        _response("here is your key: ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"),
        "server_to_client",
        _session(),
    )
    assert decision.action == "block"
    assert decision.rule == "secrets_in_response"
