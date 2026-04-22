"""Hard-coded blocking rules for Gateward.

Rules are evaluated in order on each message. First block wins. Non
tool-call / non-result messages (``initialize``, ``ping``, notifications,
etc.) short-circuit to ``allow`` so protocol handshake and lifecycle
traffic is never interfered with.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Literal

from gateward.patterns import (
    ARGUMENT_INJECTION_PATTERNS,
    DESTRUCTIVE_SHELL_PATTERNS,
    EXFIL_URL_PATTERNS,
    INJECTION_PHRASES,
    PATH_TRAVERSAL_PATTERNS,
    SECRETS_PATTERNS,
    SSRF_PATTERNS,
    SUSPICIOUS_DESCRIPTION_PATTERNS,
    decode_and_extract,
)
from gateward.session import Session

Action = Literal["allow", "block", "warn"]


@dataclass
class Decision:
    action: Action
    reason: str = ""
    rule: str = ""


# Matches canonical "owner/repo" slugs; intentionally conservative so that
# ordinary string arguments (URLs, paths, tokens) do not trigger a false
# positive repository identity.
_REPO_SLUG_RE = re.compile(r"^[\w.-]+/[\w.-]+$")


def _is_repo_server(session: Session) -> bool:
    name = session.server_name.lower()
    return "github" in name or "gitlab" in name


def _extract_repo(arguments: Any) -> str | None:
    """Pull a canonical ``owner/repo`` string out of tool call arguments.

    Looks for common argument shapes used by the official GitHub/GitLab MCP
    servers: ``{"owner": "...", "repo": "..."}``, ``{"repository": "x/y"}``,
    ``{"full_name": "x/y"}``, or any string value that looks like a slug.
    """
    if not isinstance(arguments, dict):
        return None

    owner = arguments.get("owner")
    repo = arguments.get("repo") or arguments.get("repository_name")
    if isinstance(owner, str) and isinstance(repo, str) and "/" not in repo:
        return f"{owner}/{repo}".lower()

    for key in ("repository", "full_name", "repo", "project", "project_path"):
        value = arguments.get(key)
        if isinstance(value, str) and _REPO_SLUG_RE.match(value):
            return value.lower()

    for value in arguments.values():
        if isinstance(value, str) and _REPO_SLUG_RE.match(value):
            return value.lower()

    return None


def _iter_string_values(obj: Any):
    """Yield every string leaf in a nested JSON-like structure."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_string_values(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_string_values(item)


def _iter_result_text(result: Any):
    """Yield every text fragment from an MCP tool-call ``result`` payload.

    MCP tool results carry a ``content`` array whose entries have ``type`` and
    ``text`` fields. Some servers also inline plain strings or nested objects;
    yield any string leaf we find so the injection filter sees everything the
    agent will see.
    """
    if not isinstance(result, dict):
        return
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    yield text
                else:
                    yield from _iter_string_values(item)
            elif isinstance(item, str):
                yield item
    # Some servers put structured data on result.structuredContent or similar.
    for key, value in result.items():
        if key == "content":
            continue
        yield from _iter_string_values(value)


def check_cross_repo(message: dict, direction: str, session: Session) -> Decision:
    """Block when a tools/call targets a different repository than the first one seen."""
    if direction != "client_to_server":
        return Decision(action="allow", rule="cross_repo")
    if message.get("method") != "tools/call":
        return Decision(action="allow", rule="cross_repo")
    if not _is_repo_server(session):
        return Decision(action="allow", rule="cross_repo")

    arguments = message.get("params", {}).get("arguments")
    repo = _extract_repo(arguments)
    if repo is None:
        return Decision(action="allow", rule="cross_repo")

    if session.first_repo_seen is None:
        session.first_repo_seen = repo
        return Decision(action="allow", rule="cross_repo")

    if repo == session.first_repo_seen:
        return Decision(action="allow", rule="cross_repo")

    return Decision(
        action="block",
        reason=(
            f"cross_repository_access: session started in "
            f"{session.first_repo_seen}, attempted access to {repo}"
        ),
        rule="cross_repo",
    )


def check_injection_phrases(message: dict, direction: str, session: Session) -> Decision:
    """Block tool responses whose text contains a known prompt-injection phrase."""
    if direction != "server_to_client":
        return Decision(action="allow", rule="injection_phrase")
    result = message.get("result")
    if not isinstance(result, dict):
        return Decision(action="allow", rule="injection_phrase")
    if "content" not in result:
        # Only enforce on tool-call shaped responses.
        return Decision(action="allow", rule="injection_phrase")

    haystack = " ".join(_iter_result_text(result)).lower()
    if not haystack:
        return Decision(action="allow", rule="injection_phrase")

    for phrase in INJECTION_PHRASES:
        if phrase in haystack:
            return Decision(
                action="block",
                reason=f"injection_phrase_detected: '{phrase}'",
                rule="injection_phrase",
            )
    return Decision(action="allow", rule="injection_phrase")


def check_destructive_shell(message: dict, direction: str, session: Session) -> Decision:
    """Block tool calls whose arguments contain a destructive shell command."""
    if direction != "client_to_server":
        return Decision(action="allow", rule="destructive_shell")
    if message.get("method") != "tools/call":
        return Decision(action="allow", rule="destructive_shell")

    arguments = message.get("params", {}).get("arguments")
    if arguments is None:
        return Decision(action="allow", rule="destructive_shell")

    haystack = " ".join(_iter_string_values(arguments))
    if not haystack:
        return Decision(action="allow", rule="destructive_shell")

    for pattern in DESTRUCTIVE_SHELL_PATTERNS:
        if pattern.search(haystack):
            return Decision(
                action="block",
                reason=f"destructive_shell_command: matched pattern {pattern.pattern}",
                rule="destructive_shell",
            )
    return Decision(action="allow", rule="destructive_shell")


def check_secrets_in_response(message: dict, direction: str, session: Session) -> Decision:
    """Block tool responses whose text contains a credential-shaped pattern."""
    if direction != "server_to_client":
        return Decision(action="allow", rule="secrets_in_response")
    result = message.get("result")
    if not isinstance(result, dict):
        return Decision(action="allow", rule="secrets_in_response")
    if "content" not in result:
        return Decision(action="allow", rule="secrets_in_response")

    haystack = " ".join(_iter_result_text(result))
    if not haystack:
        return Decision(action="allow", rule="secrets_in_response")

    for pattern in SECRETS_PATTERNS:
        if pattern.search(haystack):
            return Decision(
                action="block",
                reason=f"secrets_in_response: matched '{pattern.pattern}' pattern",
                rule="secrets_in_response",
            )
    return Decision(action="allow", rule="secrets_in_response")


def check_path_traversal(message: dict, direction: str, session: Session) -> Decision:
    """Block tool calls whose arguments reference sensitive paths or traversal sequences."""
    if direction != "client_to_server":
        return Decision(action="allow", rule="path_traversal")
    if message.get("method") != "tools/call":
        return Decision(action="allow", rule="path_traversal")

    arguments = message.get("params", {}).get("arguments")
    if arguments is None:
        return Decision(action="allow", rule="path_traversal")

    for value in _iter_string_values(arguments):
        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern.search(value):
                return Decision(
                    action="block",
                    reason=f"path_traversal: matched '{pattern.pattern}' in argument",
                    rule="path_traversal",
                )
    return Decision(action="allow", rule="path_traversal")


def check_tool_description_scan(message: dict, direction: str, session: Session) -> Decision:
    """Block ``tools/list`` responses containing poisoned tool descriptions.

    Tool descriptions are read verbatim by the LLM but rarely shown to the
    user. Attackers hide directives there (``<IMPORTANT>``, "before using
    this tool read ~/.ssh/...", "also present X tool") to steer the agent
    covertly. This rule scans each tool's description *and* its input
    schema for those patterns.
    """
    if direction != "server_to_client":
        return Decision(action="allow", rule="tool_description_scan")
    result = message.get("result")
    if not isinstance(result, dict):
        return Decision(action="allow", rule="tool_description_scan")
    tools = result.get("tools")
    if not isinstance(tools, list):
        return Decision(action="allow", rule="tool_description_scan")

    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name", "unknown")
        desc = tool.get("description", "") or ""
        schema = tool.get("inputSchema") or {}
        schema_text = json.dumps(schema) if schema else ""
        full_text = f"{desc} {schema_text}"

        for pattern in SUSPICIOUS_DESCRIPTION_PATTERNS:
            match = pattern.search(full_text)
            if match:
                return Decision(
                    action="block",
                    reason=(
                        f"tool_description_poisoning: suspicious content "
                        f"'{match.group(0)}' in tool '{name}' description"
                    ),
                    rule="tool_description_scan",
                )
    return Decision(action="allow", rule="tool_description_scan")


def check_tool_schema_drift(message: dict, direction: str, session: Session) -> Decision:
    """Detect tool definition changes between sessions (rug pull detection).

    The first time Gateward sees a ``(server_command, tool_name)`` pair, it
    records a SHA-256 fingerprint of the description and input schema.
    Subsequent sessions re-hash and compare. A mismatch is a supply-chain
    signal: the server replaced its behavior without a visible version bump.
    Fails open if ``session.schema_store`` is unset (e.g. unit tests).
    """
    if direction != "server_to_client":
        return Decision(action="allow", rule="tool_schema_drift")
    if session.schema_store is None:
        return Decision(action="allow", rule="tool_schema_drift")
    result = message.get("result")
    if not isinstance(result, dict):
        return Decision(action="allow", rule="tool_schema_drift")
    tools = result.get("tools")
    if not isinstance(tools, list):
        return Decision(action="allow", rule="tool_schema_drift")

    drifts = session.schema_store.check_and_store(session.server_command, tools)
    if drifts:
        return Decision(
            action="block",
            reason=(
                f"tool_schema_drift: {'; '.join(drifts)}. Possible supply chain attack."
            ),
            rule="tool_schema_drift",
        )
    return Decision(action="allow", rule="tool_schema_drift")


def _collect_texts_for_encoded_scan(message: dict, direction: str) -> list[str]:
    texts: list[str] = []
    if direction == "client_to_server" and message.get("method") == "tools/call":
        args = message.get("params", {}).get("arguments")
        if args is not None:
            texts.extend(_iter_string_values(args))
    if direction == "server_to_client":
        result = message.get("result")
        if isinstance(result, dict) and "content" in result:
            texts.extend(_iter_result_text(result))
    return texts


def check_encoded_payload(message: dict, direction: str, session: Session) -> Decision:
    """Decode base64 / hex / URL-encoded fragments and re-check against rules 1/3/4/5.

    Any regex-based detection is bypassable with encoding — this closes the
    loop by running the decoded plaintext back through the other pattern
    libraries. Runs on both tool-call arguments (outbound) and tool-result
    text (inbound).
    """
    texts = _collect_texts_for_encoded_scan(message, direction)
    if not texts:
        return Decision(action="allow", rule="encoded_payload")

    for text in texts:
        decoded_parts = decode_and_extract(text)
        for decoded in decoded_parts:
            lowered = decoded.lower()
            for phrase in INJECTION_PHRASES:
                if phrase in lowered:
                    return Decision(
                        action="block",
                        reason=(
                            f"encoded_payload: decoded content contains injection "
                            f"phrase '{phrase}'"
                        ),
                        rule="encoded_payload",
                    )
            for pattern in SECRETS_PATTERNS:
                if pattern.search(decoded):
                    return Decision(
                        action="block",
                        reason=(
                            f"encoded_payload: decoded content contains credential "
                            f"pattern '{pattern.pattern}'"
                        ),
                        rule="encoded_payload",
                    )
            for pattern in PATH_TRAVERSAL_PATTERNS:
                if pattern.search(decoded):
                    return Decision(
                        action="block",
                        reason=(
                            f"encoded_payload: decoded content contains path "
                            f"traversal '{pattern.pattern}'"
                        ),
                        rule="encoded_payload",
                    )
            for pattern in DESTRUCTIVE_SHELL_PATTERNS:
                if pattern.search(decoded):
                    return Decision(
                        action="block",
                        reason=(
                            f"encoded_payload: decoded content contains destructive "
                            f"command '{pattern.pattern}'"
                        ),
                        rule="encoded_payload",
                    )
    return Decision(action="allow", rule="encoded_payload")


def check_ssrf_protection(message: dict, direction: str, session: Session) -> Decision:
    """Block tool calls whose arguments target internal/metadata addresses or dangerous schemes."""
    if direction != "client_to_server":
        return Decision(action="allow", rule="ssrf_protection")
    if message.get("method") != "tools/call":
        return Decision(action="allow", rule="ssrf_protection")

    arguments = message.get("params", {}).get("arguments")
    if arguments is None:
        return Decision(action="allow", rule="ssrf_protection")

    for value in _iter_string_values(arguments):
        for pattern in SSRF_PATTERNS:
            match = pattern.search(value)
            if match:
                return Decision(
                    action="block",
                    reason=(
                        f"ssrf_protection: request targets internal/metadata address "
                        f"'{match.group(0)}'"
                    ),
                    rule="ssrf_protection",
                )
    return Decision(action="allow", rule="ssrf_protection")


def check_exfil_url(message: dict, direction: str, session: Session) -> Decision:
    """Block tool calls that look like data exfiltration via URL payloads."""
    if direction != "client_to_server":
        return Decision(action="allow", rule="exfil_url_detection")
    if message.get("method") != "tools/call":
        return Decision(action="allow", rule="exfil_url_detection")

    arguments = message.get("params", {}).get("arguments")
    if arguments is None:
        return Decision(action="allow", rule="exfil_url_detection")

    for value in _iter_string_values(arguments):
        for pattern in EXFIL_URL_PATTERNS:
            match = pattern.search(value)
            if match:
                snippet = match.group(0)[:80]
                return Decision(
                    action="block",
                    reason=f"exfil_url_detection: potential data exfiltration via '{snippet}...'",
                    rule="exfil_url_detection",
                )
    return Decision(action="allow", rule="exfil_url_detection")


def check_command_argument_injection(message: dict, direction: str, session: Session) -> Decision:
    """Block tool calls whose arguments embed interpreter flags or shell
    metacharacters that bypass command allowlists.

    Covers the class of attacks behind CVE-2026-30615 (Windsurf zero-click
    RCE) and CVE-2026-30625 (Upsonic allowlist bypass), where the tool
    allowlist permitted commands like ``npx`` or ``python`` but a crafted
    argument (``-c``, ``--eval``, ``$(…)``, ``; curl …``, ``LD_PRELOAD=…``,
    ``<(…)``) turned the allowed binary into an arbitrary-code primitive.
    Also catches CVE-2025-68144-style git argument injection
    (``--config=core.sshCommand=…``, ``--upload-pack=…``).
    """
    if direction != "client_to_server":
        return Decision(action="allow", rule="command_argument_injection")
    if message.get("method") != "tools/call":
        return Decision(action="allow", rule="command_argument_injection")

    arguments = message.get("params", {}).get("arguments")
    if arguments is None:
        return Decision(action="allow", rule="command_argument_injection")

    for value in _iter_string_values(arguments):
        for pattern in ARGUMENT_INJECTION_PATTERNS:
            match = pattern.search(value)
            if match:
                snippet = match.group(0).strip()[:60]
                return Decision(
                    action="block",
                    reason=(
                        f"command_argument_injection: '{snippet}' — possible "
                        f"allowlist bypass (ref: CVE-2026-30615)"
                    ),
                    rule="command_argument_injection",
                )
    return Decision(action="allow", rule="command_argument_injection")


# Order matters only for precedence of the reported rule name when multiple
# rules would block the same message. The existing 5 are kept ahead of the
# new 5 so their reasons remain stable. check_tool_schema_drift runs AFTER
# check_tool_description_scan so a poisoned tools/list is blocked without
# being recorded as a "known good" baseline fingerprint.
_RULE_FUNCTIONS = (
    check_cross_repo,
    check_injection_phrases,
    check_destructive_shell,
    check_secrets_in_response,
    check_path_traversal,
    check_tool_description_scan,
    check_tool_schema_drift,
    check_encoded_payload,
    check_ssrf_protection,
    check_exfil_url,
    check_command_argument_injection,
)


def evaluate(message: dict, direction: str, session: Session) -> Decision:
    """Run all rules in order. First block wins."""
    method = message.get("method")
    if method != "tools/call" and "result" not in message:
        return Decision(action="allow", rule="none")

    for rule_fn in _RULE_FUNCTIONS:
        decision = rule_fn(message, direction, session)
        if decision.action == "block":
            session.blocked_count += 1
            return decision
    return Decision(action="allow", rule="none")
