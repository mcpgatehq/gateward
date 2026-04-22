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


# Human-readable labels shown in the report header for each rule name.
_RULE_TITLES: dict[str, str] = {
    "tool_poisoning": "Tool Description Poisoning",
    "injection_in_description": "Injection Phrase in Description",
    "unicode_hiding": "Invisible Unicode in Description",
    "shell_execution": "Shell Command Execution",
    "file_access": "File Path Access",
    "network_access": "Network / URL Access",
    "sql_execution": "SQL Query Execution",
    "dangerous_capability": "Dangerous Capability",
    "large_attack_surface": "Large Attack Surface",
    "connection": "Connection",
}


# Per-rule impact narrative and authoritative reference, used by the report
# renderer. Keep these short (one line each) — the renderer already shows
# the scanner's finding detail above them.
FINDING_DETAILS: dict[str, dict[str, str | None]] = {
    "tool_poisoning": {
        "impact": "Tool descriptions are injected into AI context. An attacker can hide instructions that hijack the agent.",
        "ref": "MCPTox benchmark — 84.2% attack success rate",
    },
    "injection_in_description": {
        "impact": "Tool descriptions contain phrases designed to override agent behavior.",
        "ref": "Invariant Labs tool poisoning (April 2025)",
    },
    "unicode_hiding": {
        "impact": "Invisible characters can hide malicious instructions from human review while remaining visible to AI.",
        "ref": "CVE-2021-42574 (Trojan Source)",
    },
    "shell_execution": {
        "impact": "Attacker can execute arbitrary code on your system.",
        "ref": "CVE-2026-30615 (Windsurf), CVE-2026-30625 (Upsonic)",
    },
    "file_access": {
        "impact": "Attacker can read files outside the intended directory.",
        "ref": "CVE-2025-68143, CVE-2025-68145 (Git MCP)",
    },
    "network_access": {
        "impact": "Attacker can access internal networks and cloud metadata.",
        "ref": "AWS metadata theft (169.254.169.254)",
    },
    "sql_execution": {
        "impact": "Attacker can read, modify, or delete database contents.",
        "ref": "Supabase/Cursor incident (July 2025)",
    },
    "dangerous_capability": {
        "impact": "Tool has inherently risky capabilities. Ensure proper access controls.",
        "ref": None,
    },
    "large_attack_surface": {
        "impact": "More tools means more potential attack vectors. Apply least-privilege.",
        "ref": None,
    },
    "connection": {
        "impact": "Could not connect to the MCP server. Check the server command.",
        "ref": None,
    },
}


def _pretty_rule(rule: str) -> str:
    return _RULE_TITLES.get(rule, rule.replace("_", " ").title())


def print_report(
    score: float,
    findings: list[dict],
    tools: list[dict],
    server_info: dict,
    server_command: list[str],
    duration_seconds: float,
) -> None:
    """Render the enterprise-grade terminal report."""
    from datetime import datetime, timezone

    from rich.console import Console
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text

    console = Console()

    # -------- Header --------
    server_name = server_info.get("name", "unknown")
    server_version = server_info.get("version", "?")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    target = " ".join(server_command)

    header_body = Text()
    header_body.append("GATEWARD", style="bold cyan")
    header_body.append("   ", style="")
    header_body.append("Security Scanner v0.3.0", style="dim")

    console.print()
    console.print(Panel(header_body, border_style="cyan", padding=(0, 2), expand=False))
    console.print()

    info = Table.grid(padding=(0, 2))
    info.add_column(style="dim", no_wrap=True)
    info.add_column(overflow="fold")
    info.add_row("Target", Text(target, style="bold"))
    info.add_row("Server", f"{server_name} v{server_version}")
    info.add_row("Tools", str(len(tools)))
    info.add_row("Duration", f"{duration_seconds:.2f}s")
    info.add_row("Scanned", timestamp)
    console.print(info)
    console.print()
    console.print(Rule(characters="━", style="dim"))
    console.print()

    # -------- Score --------
    score_int = int(round(score))
    if score_int >= 8:
        score_color, score_label = "green", "SECURE"
    elif score_int >= 4:
        score_color, score_label = "yellow", "AT RISK"
    else:
        score_color, score_label = "red", "HIGH RISK"

    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    warning_count = sum(1 for f in findings if f.get("severity") == "WARNING")

    filled = max(0, min(10, score_int))
    empty = 10 - filled
    bar = Text()
    bar.append("█" * filled, style=score_color)
    bar.append("░" * empty, style="dim")

    score_line = Text()
    score_line.append("Security Score   ", style="bold")
    score_line.append(f"{score_int}/10", style=f"bold {score_color}")
    score_line.append("   ")
    score_line.append_text(bar)
    score_line.append(f"   {score_label}", style=f"bold {score_color}")
    console.print(score_line)

    summary = Text()
    summary.append(
        f"{critical_count} CRITICAL", style="red bold" if critical_count else "dim"
    )
    summary.append("   ·   ", style="dim")
    summary.append(f"{high_count} HIGH", style="yellow bold" if high_count else "dim")
    summary.append("   ·   ", style="dim")
    summary.append(f"{warning_count} WARNING", style="yellow" if warning_count else "dim")
    console.print(summary)
    console.print()

    if score_int == 10 and not findings:
        console.print(
            Panel(
                Text.from_markup(
                    "[green bold]No security issues detected.[/green bold]\n"
                    "[dim]This MCP server passed all Gateward checks.[/dim]"
                ),
                border_style="green",
                padding=(0, 2),
                expand=False,
            )
        )
        console.print()

    # -------- Findings (deduplicated) --------
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for finding in findings:
        key = (finding.get("severity"), finding.get("rule"), finding.get("tool"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    if deduped:
        for severity, icon, color in (
            ("CRITICAL", "✗", "red"),
            ("HIGH", "✗", "yellow"),
            ("WARNING", "⚠", "yellow"),
        ):
            subset = [f for f in deduped if f.get("severity") == severity]
            if not subset:
                continue

            header = Text()
            header.append(f"{severity} FINDINGS", style=f"bold {color}")
            header.append(f"   ({len(subset)})", style="dim")
            console.print(header)
            console.print()

            for finding in subset:
                rule = finding.get("rule", "") or ""
                tool = finding.get("tool", "") or ""
                detail = finding.get("detail", "") or ""
                info_entry = FINDING_DETAILS.get(rule, {})

                title = Text()
                title.append(f"  {icon}  ", style=color)
                title.append(_pretty_rule(rule), style=f"bold {color}")
                if tool:
                    title.append("   ", style="")
                    title.append(tool, style="dim")
                console.print(title)

                console.print(Text(f"     {detail}"))
                impact = info_entry.get("impact") if info_entry else None
                if impact:
                    imp = Text()
                    imp.append("     Impact  ", style="dim")
                    imp.append(impact, style="italic")
                    console.print(imp)
                ref = info_entry.get("ref") if info_entry else None
                if ref:
                    rline = Text()
                    rline.append("     Ref     ", style="dim")
                    rline.append(ref, style="dim")
                    console.print(rline)
                console.print()

    # -------- Passed checks (compact) --------
    failed_rules = {f.get("rule") for f in findings}
    passed = sorted(_ALL_RULE_NAMES - failed_rules)
    if passed:
        console.print(Rule(characters="━", style="dim"))
        console.print()
        console.print(Text(f"PASSED CHECKS   ({len(passed)})", style="bold green"))
        console.print()
        for rule in passed:
            line = Text()
            line.append("  ✓  ", style="green")
            line.append(_pretty_rule(rule), style="dim")
            console.print(line)
        console.print()

    # -------- Tools table --------
    if tools:
        console.print(Rule(characters="━", style="dim"))
        console.print()
        console.print(Text("TOOLS ANALYZED", style="bold"))
        console.print()

        severity_rank = {"CRITICAL": 3, "HIGH": 2, "WARNING": 1}
        tool_risk: dict[str, str] = {}
        for finding in findings:
            tool_name = finding.get("tool")
            if not tool_name:
                continue
            sev = finding.get("severity")
            if sev not in severity_rank:
                continue
            current = tool_risk.get(tool_name)
            if current is None or severity_rank[sev] > severity_rank[current]:
                tool_risk[tool_name] = sev

        table = Table(
            show_edge=False,
            show_lines=False,
            pad_edge=False,
            box=None,
            padding=(0, 2),
        )
        table.add_column("#", justify="right", style="dim", width=3)
        table.add_column("Name", style="bold", no_wrap=True)
        table.add_column("Parameters", style="dim")
        table.add_column("Risk", width=10)

        for idx, tool in enumerate(tools, 1):
            name = tool.get("name", "?")
            schema = tool.get("inputSchema", {}) or {}
            props = schema.get("properties", {}) if isinstance(schema, dict) else {}
            if isinstance(props, dict) and props:
                keys = list(props.keys())
                params_str = ", ".join(keys[:5])
                if len(keys) > 5:
                    params_str += f", +{len(keys) - 5}"
            else:
                params_str = "—"

            risk = tool_risk.get(name, "NONE")
            if risk == "CRITICAL":
                risk_cell: Text = Text("CRITICAL", style="red bold")
            elif risk == "HIGH":
                risk_cell = Text("HIGH", style="yellow bold")
            elif risk == "WARNING":
                risk_cell = Text("WARNING", style="yellow")
            else:
                risk_cell = Text("NONE", style="green dim")
            table.add_row(str(idx), name, params_str, risk_cell)

        console.print(table)
        console.print()

    # -------- Remediation --------
    if score_int < 10:
        console.print(Rule(characters="━", style="dim"))
        console.print()
        before_cmd = server_command[0]
        before_args = json.dumps(server_command[1:])
        after_args = ", ".join(json.dumps(a) for a in server_command[1:])

        body = Text()
        body.append("Recommended fix\n\n", style="bold")
        body.append("Wrap the MCP server with ", style="")
        body.append("gateward run", style="bold cyan")
        body.append(":\n\n", style="")
        body.append("  pip install gateward\n\n", style="green")
        body.append("Client config — before:\n", style="dim")
        body.append(f'  "command": "{before_cmd}",\n', style="red")
        body.append(f'  "args": {before_args}\n\n', style="red")
        body.append("Client config — after:\n", style="dim")
        body.append('  "command": "gateward",\n', style="green")
        body.append(
            f'  "args": ["run", "--", "{before_cmd}", {after_args}]\n\n',
            style="green",
        )
        body.append("All 12 security rules enforced at runtime.\n", style="dim")
        body.append("https://github.com/mcpgatehq/gateward", style="cyan")

        console.print(
            Panel(
                body,
                border_style="green",
                title="[bold green]REMEDIATION[/bold green]",
                title_align="left",
                padding=(1, 2),
            )
        )
        console.print()

    # -------- Footer --------
    console.print(Rule(characters="━", style="dim"))
    console.print()
    footer = Text()
    footer.append("Scan complete. ", style="dim")
    footer.append("Report generated by ", style="dim")
    footer.append("Gateward v0.3.0", style="dim cyan")
    console.print(footer)
    console.print()
