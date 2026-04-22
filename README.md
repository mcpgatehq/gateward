# Gateward

**Security gateway for MCP traffic. 12 rules. 172 tests. One pip install.**

Gateward sits between your AI agent and any MCP server, inspecting every JSON-RPC message in both directions. It blocks prompt injection, credential leakage, command injection, data exfiltration, and supply chain poisoning — before threats reach your model or your infrastructure.

## Why

Between January and April 2026, researchers filed [14 CVEs](https://github.com/mcpgatehq/gateward) targeting MCP servers. AWS, Atlassian, VS Code, Windsurf, Claude Code — all compromised through the same protocol. Anthropic has stated these behaviors are "expected" and will not be patched. Gateward is the defense-in-depth layer the ecosystem needs.

## Quick Start

```bash
pip install gateward
```

Change one line in your MCP client config:

```json
{
  "mcpServers": {
    "github": {
      "command": "gateward",
      "args": ["run", "--", "npx", "@modelcontextprotocol/server-github"]
    }
  }
}
```

That's it. 12 security rules are now active. Every message is logged to `~/.gateward/audit.db`.

## Scan Any MCP Server

Before you trust an MCP server, scan it:

```bash
gateward scan -- npx @modelcontextprotocol/server-github
```

Gateward connects to the server, analyzes all tool definitions, and produces a security score:

```
GATEWARD SECURITY SCAN REPORT
evil-server v1.0.0

Security Score:  0/10  ░░░░░░░░░░░░░░░░░░░░  HIGH RISK
Tools found:     6
Issues found:    8

2 CRITICAL · 3 HIGH · 3 WARNING

CRITICAL FINDINGS

  ✗  Tool Description Poisoning — add
     Suspicious content in description: '<IMPORTANT>'
     Impact: Tool descriptions are injected into AI context.
     Ref: MCPTox benchmark — 84.2% attack success rate

  ✗  Command Injection Risk — execute_command
     Accepts shell commands via: command
     Impact: Attacker can execute arbitrary code on your system.
     Ref: CVE-2026-30615 (Windsurf), CVE-2026-30625 (Upsonic)
```

Use `--json-output` for CI/CD integration.

## 12 Security Rules

### Core Defense

| # | Rule | Blocks | Evidence |
|---|------|--------|----------|
| 1 | `injection_phrase` | Prompt injection in tool responses | Invariant Labs, Supabase incident |
| 2 | `cross_repository_access` | Lateral movement between repos | Invariant Labs GitHub heist |
| 3 | `destructive_shell` | `rm -rf`, `DROP TABLE`, fork bombs | Filesystem MCP CVEs |
| 4 | `secrets_in_response` | API keys, tokens, SSH keys in responses | CVE-2025-59536 |
| 5 | `path_traversal` | `../../etc/passwd`, symlink escape | CVE-2025-68143/68144/68145 |

### Supply Chain Defense

| # | Rule | Blocks | Evidence |
|---|------|--------|----------|
| 6 | `tool_description_scan` | Poisoned tool descriptions, `<IMPORTANT>` tags | MCPTox 84.2% attack success rate |
| 7 | `tool_schema_drift` | Tool definitions that changed since last session | Postmark MCP rug pull |

### Bypass Prevention

| # | Rule | Blocks | Evidence |
|---|------|--------|----------|
| 8 | `encoded_payload` | Base64/hex/URL-encoded payloads hiding attacks | Standard WAF bypass technique |

### Network Defense

| # | Rule | Blocks | Evidence |
|---|------|--------|----------|
| 9 | `ssrf_protection` | Internal network access, cloud metadata theft | AWS metadata endpoint |
| 10 | `exfil_url_detection` | Data exfiltration via URLs, webhooks, curl | WhatsApp MCP heist |

### Zero-Day Defense

| # | Rule | Blocks | Evidence |
|---|------|--------|----------|
| 11 | `command_argument_injection` | `npx -c`, `python -c`, `git --config`, `LD_PRELOAD` | CVE-2026-30615, CVE-2026-30625 |
| 12 | `canary_token_tripwire` | Data theft via any method — known or unknown | Novel — no equivalent exists |

**Rule 12** is the flagship differentiator. Gateward injects invisible markers into every tool response. If a marker appears in any outbound request, the agent is copying raw data — proof of exfiltration regardless of attack method. This catches zero-day attacks that bypass all pattern-based rules. No other MCP security tool does this.

## CVE Coverage

Gateward v0.3.0 blocks 12 of 14 MCP-related CVEs published in the last 30 days:

| CVE | CVSS | Target | Rule |
|-----|------|--------|------|
| CVE-2026-30615 | Critical | Windsurf | 11 |
| CVE-2026-30625 | Critical | Upsonic | 11 |
| CVE-2026-5058 | 9.8 | AWS MCP Server | 3, 11 |
| CVE-2026-21518 | High | VS Code | 11 |
| CVE-2026-27825 | 9.1 | Atlassian MCP | 9, 11 |
| CVE-2026-27826 | 8.2 | Atlassian MCP | 9 |
| CVE-2026-33032 | Critical | nginx-ui (actively exploited) | 9 |
| CVE-2025-59536 | 8.7 | Claude Code | 4 |
| CVE-2025-6514 | 9.6 | mcp-remote (437K downloads) | 11 |
| CVE-2025-68143 | High | Git MCP Server | 5, 11 |
| CVE-2025-68144 | High | Git MCP Server | 11 |
| CVE-2025-68145 | High | Git MCP Server | 5 |

## CLI

```bash
gateward run -- <server-command>      # Proxy with 12 rules active
gateward scan -- <server-command>     # Security scan with score report
gateward scan --json-output -- <cmd>  # JSON output for CI/CD
gateward tail                         # View audit log
gateward tail --follow                # Stream audit log
gateward tail --session <id>          # Filter by session
gateward drift                        # View tool fingerprints
gateward drift --reset                # Clear all fingerprints
```

## How It Works

```
Agent ──→ Gateward ──→ MCP Server
          │                │
          │ Outbound:      │ Inbound:
          │ Rules 3,5,8,   │ Rules 1,4,6,
          │ 9,10,11,12     │ 7,8 + canary
          │                │
          └──── audit.db ──┘
```

- **Outbound** (agent → server): Inspects tool call arguments for destructive commands, path traversal, SSRF, exfiltration URLs, argument injection, and canary markers.
- **Inbound** (server → agent): Inspects tool responses for injection phrases, leaked credentials, poisoned descriptions, schema changes, and encoded payloads. Injects canary markers.
- **Session**: Tracks repository access to prevent cross-repo exfiltration.
- **Audit**: Every message logged to `~/.gateward/audit.db` with decision (ALLOW/BLOCK) and reason.

## Requirements

- Python 3.11+
- Linux or macOS
- Works with: Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, any MCP client

## Known Limitations

- **Stdio transport only.** HTTP/SSE not yet supported.
- **Rules are hard-coded.** No config file or policy DSL.
- **No alerting.** No webhook, email, or Slack notifications.
- **No web UI.** CLI only.
- **Linux/macOS only.** Windows not supported.

## License

Apache 2.0
