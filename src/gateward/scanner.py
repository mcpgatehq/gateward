"""``gateward scan`` — dynamic security scanner for MCP servers.

Spawns the target MCP server, performs a normal initialize + tools/list
handshake, and then runs a battery of checks over the returned tool
catalog. Produces a 0-10 security score plus a list of findings keyed by
severity (CRITICAL / HIGH / WARNING).

Dynamic, not static: we scan what the server actually advertises at
runtime, which catches poisoned descriptions and schema changes that a
config-file-only scanner would miss.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from gateward.patterns import INJECTION_PHRASES, SUSPICIOUS_DESCRIPTION_PATTERNS


# Zero-width and bidi-override characters that can hide prompt-injection
# text inside an otherwise innocent-looking tool description.
_INVISIBLE_UNICODE_CODEPOINTS = frozenset(
    {
        0x200B, 0x200C, 0x200D, 0x200E, 0x200F,
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
        0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
        0xFEFF, 0x00AD,
    }
)


_DANGEROUS_NAME_CATEGORIES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(run|exec|execute|shell|bash|system)"), "Command execution tool"),
    (re.compile(r"(?i)(delete|remove|drop|truncate|destroy)"), "Destructive operation tool"),
    (re.compile(r"(?i)(write|create|modify|update).*file"), "File write tool"),
    (re.compile(r"(?i)(send|post|upload|transmit)"), "Data transmission tool"),
]


_SHELL_PARAMS = frozenset({"command", "cmd", "shell", "exec", "eval", "script", "code"})
_FILE_PARAMS = frozenset({"path", "file", "filename", "directory"})
_NETWORK_PARAMS = frozenset({"url", "uri", "endpoint", "webhook"})
_SQL_PARAMS = frozenset({"query", "sql"})
_RISKY_PARAMS = _SHELL_PARAMS | _FILE_PARAMS | _NETWORK_PARAMS | _SQL_PARAMS


class MCPScanner:
    """Connects to an MCP server, probes for vulnerabilities, produces a security report."""

    def __init__(self, server_command: list[str]) -> None:
        self.server_command = server_command
        self.findings: list[dict[str, Any]] = []
        self.tools: list[dict[str, Any]] = []
        self.server_info: dict[str, Any] = {}
        self.process: asyncio.subprocess.Process | None = None

    async def scan(self) -> tuple[float, list[dict], list[dict], dict]:
        try:
            await self._start_server()
            await self._initialize()
            await self._get_tools()

            self._check_tool_descriptions()
            self._check_tool_schemas()
            self._check_dangerous_tool_names()
            self._check_tool_count()

            score = self._calculate_score()
            return score, self.findings, self.tools, self.server_info
        finally:
            await self._stop_server()

    async def _start_server(self) -> None:
        self.process = await asyncio.create_subprocess_exec(
            *self.server_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def _send_and_receive(self, message: dict, timeout: float = 10.0) -> dict | None:
        assert self.process is not None and self.process.stdin is not None and self.process.stdout is not None
        data = json.dumps(message) + "\n"
        self.process.stdin.write(data.encode())
        try:
            await self.process.stdin.drain()
        except (ConnectionError, BrokenPipeError, OSError):
            return None

        try:
            line = await asyncio.wait_for(self.process.stdout.readline(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
        if not line:
            return None
        try:
            return json.loads(line.decode().strip())
        except json.JSONDecodeError:
            return None

    async def _initialize(self) -> None:
        response = await self._send_and_receive(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "gateward-scanner", "version": "0.3.0"},
                },
            }
        )
        if response and "result" in response:
            self.server_info = response["result"].get("serverInfo", {}) or {}
            assert self.process is not None and self.process.stdin is not None
            notif = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) + "\n"
            self.process.stdin.write(notif.encode())
            try:
                await self.process.stdin.drain()
            except (ConnectionError, BrokenPipeError, OSError):
                pass
            await asyncio.sleep(0.2)
        else:
            self.findings.append(
                {"severity": "CRITICAL", "rule": "connection", "detail": "Failed to initialize MCP connection"}
            )

    async def _get_tools(self) -> None:
        response = await self._send_and_receive(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        )
        if response and "result" in response:
            tools = response["result"].get("tools", []) or []
            if isinstance(tools, list):
                self.tools = [t for t in tools if isinstance(t, dict)]
        else:
            self.findings.append(
                {"severity": "WARNING", "rule": "connection", "detail": "Failed to retrieve tools list"}
            )

    def _check_tool_descriptions(self) -> None:
        for tool in self.tools:
            name = tool.get("name", "unknown")
            desc = tool.get("description", "") or ""
            schema_text = json.dumps(tool.get("inputSchema", {}) or {})
            full_text = f"{desc} {schema_text}"

            for pattern in SUSPICIOUS_DESCRIPTION_PATTERNS:
                match = pattern.search(full_text)
                if match:
                    self.findings.append(
                        {
                            "severity": "CRITICAL",
                            "rule": "tool_poisoning",
                            "tool": name,
                            "detail": f"Suspicious content in description: '{match.group(0)}'",
                        }
                    )
                    break

            desc_lower = desc.lower()
            for phrase in INJECTION_PHRASES:
                if phrase in desc_lower:
                    self.findings.append(
                        {
                            "severity": "CRITICAL",
                            "rule": "injection_in_description",
                            "tool": name,
                            "detail": "Tool description contains injection phrases",
                        }
                    )
                    break

            invisible_count = sum(1 for c in full_text if ord(c) in _INVISIBLE_UNICODE_CODEPOINTS)
            if invisible_count > 0:
                self.findings.append(
                    {
                        "severity": "CRITICAL",
                        "rule": "unicode_hiding",
                        "tool": name,
                        "detail": f"{invisible_count} invisible Unicode characters in description",
                    }
                )

    def _check_tool_schemas(self) -> None:
        for tool in self.tools:
            name = tool.get("name", "unknown")
            schema = tool.get("inputSchema", {}) or {}
            properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
            if not isinstance(properties, dict):
                continue

            risky = [p for p in properties.keys() if p.lower() in _RISKY_PARAMS]
            if not risky:
                continue

            lowered = {p.lower() for p in risky}
            if lowered & _SHELL_PARAMS:
                self.findings.append(
                    {
                        "severity": "CRITICAL",
                        "rule": "shell_execution",
                        "tool": name,
                        "detail": (
                            f"Accepts shell commands via: {', '.join(sorted(risky))}. "
                            f"Vulnerable to command injection (CVE-2026-30615)."
                        ),
                    }
                )
            if lowered & _FILE_PARAMS:
                self.findings.append(
                    {
                        "severity": "HIGH",
                        "rule": "file_access",
                        "tool": name,
                        "detail": (
                            f"Accepts file paths via: {', '.join(sorted(risky))}. "
                            f"Vulnerable to path traversal (CVE-2025-68145)."
                        ),
                    }
                )
            if lowered & _NETWORK_PARAMS:
                self.findings.append(
                    {
                        "severity": "HIGH",
                        "rule": "network_access",
                        "tool": name,
                        "detail": (
                            f"Accepts URLs via: {', '.join(sorted(risky))}. Vulnerable to SSRF."
                        ),
                    }
                )
            if lowered & _SQL_PARAMS:
                self.findings.append(
                    {
                        "severity": "HIGH",
                        "rule": "sql_execution",
                        "tool": name,
                        "detail": (
                            f"Accepts SQL queries via: {', '.join(sorted(risky))}. "
                            f"Vulnerable to SQL injection."
                        ),
                    }
                )

    def _check_dangerous_tool_names(self) -> None:
        for tool in self.tools:
            name = tool.get("name", "unknown")
            for pattern, category in _DANGEROUS_NAME_CATEGORIES:
                if pattern.search(name):
                    self.findings.append(
                        {
                            "severity": "WARNING",
                            "rule": "dangerous_capability",
                            "tool": name,
                            "detail": f"{category} — requires careful access control",
                        }
                    )
                    break

    def _check_tool_count(self) -> None:
        if len(self.tools) > 20:
            self.findings.append(
                {
                    "severity": "WARNING",
                    "rule": "large_attack_surface",
                    "detail": (
                        f"Server exposes {len(self.tools)} tools. More tools = larger "
                        f"attack surface. Consider least-privilege."
                    ),
                }
            )

    def _calculate_score(self) -> float:
        if not self.tools:
            return 0.0
        score = 10.0
        for finding in self.findings:
            severity = finding.get("severity")
            if severity == "CRITICAL":
                score -= 2.5
            elif severity == "HIGH":
                score -= 1.5
            elif severity == "WARNING":
                score -= 0.5
        return max(0.0, min(10.0, round(score, 1)))

    async def _stop_server(self) -> None:
        if self.process is None:
            return
        try:
            if self.process.stdin is not None and not self.process.stdin.is_closing():
                self.process.stdin.close()
        except Exception:
            pass
        try:
            await asyncio.wait_for(self.process.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            try:
                self.process.terminate()
                await asyncio.wait_for(self.process.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                try:
                    self.process.kill()
                except ProcessLookupError:
                    pass
                try:
                    await self.process.wait()
                except Exception:
                    pass
        except Exception:
            pass


_ALL_RULE_NAMES = {
    "tool_poisoning",
    "injection_in_description",
    "unicode_hiding",
    "shell_execution",
    "file_access",
    "network_access",
    "sql_execution",
    "dangerous_capability",
    "large_attack_surface",
}


def print_report(
    score: float,
    findings: list[dict],
    tools: list[dict],
    server_info: dict,
    server_command: list[str],
) -> None:
    """Render a colorful terminal report."""
    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    if score >= 8:
        score_color, score_label = "green", "GOOD"
    elif score >= 5:
        score_color, score_label = "yellow", "MODERATE"
    elif score >= 3:
        score_color, score_label = "red", "POOR"
    else:
        score_color, score_label = "red bold", "CRITICAL"

    filled = int(score)
    empty = 10 - filled
    score_bar = "█" * filled + "░" * empty

    server_name = server_info.get("name", "unknown")
    server_version = server_info.get("version", "?")

    console.print()
    console.print(
        Panel.fit(
            f"[bold]GATEWARD SECURITY SCAN REPORT[/bold]\n"
            f"[dim]{server_name} v{server_version}[/dim]",
            border_style="blue",
        )
    )
    console.print()
    console.print(
        f"  Security Score:  [{score_color}]{score}/10  {score_bar} {score_label}[/{score_color}]"
    )
    console.print(f"  Tools found:     {len(tools)}")
    console.print(f"  Issues found:    {len(findings)}")
    console.print()

    if findings:
        for severity in ("CRITICAL", "HIGH", "WARNING"):
            subset = [f for f in findings if f.get("severity") == severity]
            if not subset:
                continue
            if severity == "CRITICAL":
                icon, color = "[!!]", "red bold"
            elif severity == "HIGH":
                icon, color = "[!]", "red"
            else:
                icon, color = "[*]", "yellow"
            for finding in subset:
                tool_name = finding.get("tool", "")
                tool_str = f" [{tool_name}]" if tool_name else ""
                console.print(
                    f"  {icon} [{color}]{severity}[/{color}]{tool_str} — {finding.get('detail', '')}"
                )
        console.print()

    failed = {f.get("rule") for f in findings}
    passed = _ALL_RULE_NAMES - failed
    if passed:
        for rule in sorted(passed):
            console.print(f"  [OK] PASS — {rule.replace('_', ' ').title()}")
        console.print()

    before_cmd = server_command[0]
    before_args = json.dumps(server_command[1:])
    after_args_list = ", ".join(json.dumps(a) for a in server_command[1:])
    console.print(
        Panel.fit(
            f"[bold]FIX: Add Gateward as proxy[/bold]\n\n"
            f"[red]Before (vulnerable):[/red]\n"
            f'  "command": "{before_cmd}",\n'
            f'  "args": {before_args}\n\n'
            f"[green]After (protected by 12 rules):[/green]\n"
            f'  "command": "gateward",\n'
            f'  "args": ["run", "--", "{before_cmd}", {after_args_list}]\n\n'
            f"[dim]Score: {score}/10 → Protected by 12 security rules[/dim]",
            border_style="green",
        )
    )
    console.print()
