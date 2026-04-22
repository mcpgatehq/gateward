"""Rule 12 — canary tripwire (zero-day exfiltration detection).

Injects a short HTML-comment marker (``<!-- gw:XXXXXXXX -->``) into every
tool response that has text content. On the next outbound tool call, if
any previously-issued marker for this session shows up in the request
arguments, the agent is copying raw response data into an outbound
request — proof of exfiltration regardless of which attack vector got
there.

The rest of the rule library looks for *known* attack shapes. This one
looks for the *effect* of any successful attack: data leaving. That makes
it resilient against zero-days that slip past every pattern-based check.

Markers are per-session and held in memory only. They are deliberately
not persisted — the tripwire is a live-session detector, not an audit
tool, and keeping them in RAM avoids leaking the marker value if the
audit DB is read.
"""
from __future__ import annotations

import copy
import json
import secrets


def _generate_canary() -> str:
    """Return a unique, benign-looking HTML comment marker."""
    return f"<!-- gw:{secrets.token_hex(4)} -->"


class CanaryTripwire:
    def __init__(self) -> None:
        # session_id -> set of canary strings still considered "live".
        self._active: dict[str, set[str]] = {}

    def generate_canary(self) -> str:
        return _generate_canary()

    def inject_into_response(self, session_id: str, message: dict) -> dict:
        """Append a unique canary to each text fragment in ``message.result.content``.

        Returns a deep copy of the message with the canary appended; the
        original dict is not mutated so the audit log (already called on the
        pre-inject message) stays free of the marker.
        """
        if "result" not in message:
            return message
        result = message.get("result", {})
        if not isinstance(result, dict):
            return message
        content = result.get("content")
        if not content or not isinstance(content, list):
            return message

        modified = copy.deepcopy(message)
        bucket = self._active.setdefault(session_id, set())
        for item in modified["result"]["content"]:
            if isinstance(item, dict) and item.get("type") == "text" and item.get("text"):
                canary = _generate_canary()
                bucket.add(canary)
                item["text"] = item["text"] + canary
        return modified

    def check_outbound(self, session_id: str, message: dict) -> str | None:
        """Return a block reason if any live canary shows up in outbound args, else None."""
        if message.get("method") != "tools/call":
            return None
        bucket = self._active.get(session_id)
        if not bucket:
            return None

        args = message.get("params", {}).get("arguments", {})
        try:
            args_text = json.dumps(args, ensure_ascii=False)
        except (TypeError, ValueError):
            args_text = str(args)

        for canary in bucket:
            if canary in args_text:
                return (
                    f"canary_tripwire: data from previous tool response "
                    f"detected in outbound request (marker: {canary[:15]}...). "
                    f"Agent may be compromised — blocking potential data exfiltration."
                )
        return None

    def clear_session(self, session_id: str) -> None:
        self._active.pop(session_id, None)
