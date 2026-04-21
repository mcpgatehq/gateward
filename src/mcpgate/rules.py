"""Hard-coded blocking rules for MCPGate v0.1.

Three rules, evaluated in order on each message. First block wins. Non
tool-call / non-result messages (``initialize``, ``ping``, notifications,
etc.) short-circuit to ``allow`` so protocol handshake and lifecycle
traffic is never interfered with.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from mcpgate.patterns import DESTRUCTIVE_SHELL_PATTERNS, INJECTION_PHRASES
from mcpgate.session import Session

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


_RULE_FUNCTIONS = (check_cross_repo, check_injection_phrases, check_destructive_shell)


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
