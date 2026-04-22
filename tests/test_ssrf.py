"""Tests for the ssrf_protection rule (Rule 9)."""
from __future__ import annotations

from gateward.rules import check_ssrf_protection, evaluate
from gateward.session import Session


def _session() -> Session:
    return Session(server_name="fake-server", server_command="python fake.py")


def _call(arguments: dict, id_: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": id_,
        "method": "tools/call",
        "params": {"name": "fetch_url", "arguments": arguments},
    }


def test_allows_public_url():
    msg = _call({"url": "https://api.github.com/repos/octocat/hello-world"})
    assert check_ssrf_protection(msg, "client_to_server", _session()).action == "allow"


def test_blocks_localhost():
    msg = _call({"url": "http://127.0.0.1:8080/admin"})
    decision = check_ssrf_protection(msg, "client_to_server", _session())
    assert decision.action == "block"
    assert "ssrf_protection" in decision.reason


def test_blocks_aws_metadata():
    msg = _call({"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"})
    assert check_ssrf_protection(msg, "client_to_server", _session()).action == "block"


def test_blocks_internal_10():
    msg = _call({"url": "http://10.0.0.1:3000/internal"})
    assert check_ssrf_protection(msg, "client_to_server", _session()).action == "block"


def test_blocks_internal_192():
    msg = _call({"url": "http://192.168.1.1/admin"})
    assert check_ssrf_protection(msg, "client_to_server", _session()).action == "block"


def test_blocks_file_protocol():
    msg = _call({"url": "file:///etc/passwd"})
    assert check_ssrf_protection(msg, "client_to_server", _session()).action == "block"


def test_blocks_gopher():
    msg = _call({"url": "gopher://localhost:25/"})
    assert check_ssrf_protection(msg, "client_to_server", _session()).action == "block"


def test_blocks_nip_io():
    msg = _call({"url": "http://7f000001.nip.io:3000/"})
    assert check_ssrf_protection(msg, "client_to_server", _session()).action == "block"


def test_blocks_google_metadata():
    msg = _call({"url": "http://metadata.google.internal/computeMetadata/v1/"})
    assert check_ssrf_protection(msg, "client_to_server", _session()).action == "block"


def test_allows_normal_ip():
    msg = _call({"url": "http://142.250.80.46/search"})
    assert check_ssrf_protection(msg, "client_to_server", _session()).action == "allow"


def test_blocks_localhost_variant():
    msg = _call({"url": "http://localhost:8000/api"})
    assert check_ssrf_protection(msg, "client_to_server", _session()).action == "block"


def test_blocks_ipv6_loopback():
    msg = _call({"url": "http://[::1]:8080/"})
    assert check_ssrf_protection(msg, "client_to_server", _session()).action == "block"


def test_ignored_on_server_direction():
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [{"type": "text", "text": "http://127.0.0.1/"}]},
    }
    assert check_ssrf_protection(msg, "server_to_client", _session()).action == "allow"


def test_evaluate_blocks_ssrf():
    msg = _call({"url": "http://169.254.169.254/latest/meta-data/"})
    decision = evaluate(msg, "client_to_server", _session())
    assert decision.action == "block"
    assert decision.rule == "ssrf_protection"
