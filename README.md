# Gateward

Gateward blocks the prompt-injection attacks Anthropic decided not to fix at the MCP protocol level. Install in 60 seconds, defend against the Invariant Labs GitHub heist, the Supabase/Cursor SQL exfiltration, and destructive agent commands — with one line of config.

## Why this exists

Between May 2025 and April 2026, at least six public incidents demonstrated that MCP servers are an unguarded attack surface:

- **Invariant Labs (May 2025):** A malicious public GitHub issue hijacked Claude via the official GitHub MCP server and exfiltrated private repository contents to public comments.
- **Supabase/Cursor (July 2025):** Prompt injection through a support ticket caused an agent to run `service_role` SQL queries and leak a full customer table.
- **Postmark MCP (August 2025):** A compromised community MCP server silently BCC'd every outgoing email to an attacker.

Anthropic has stated these behaviors are "expected" and will not be patched at the protocol level. Gateward is defense-in-depth that sits in front of any MCP server and blocks the most-cited attack classes before they reach the model.

## Installation

```
pip install gateward
```

Python 3.11+ on Linux or macOS. Windows is not supported in v0.2.

## Quick start

Gateward wraps an existing MCP server command. Wherever your MCP client config invokes the server directly, change it to route through `gateward run --`.

For example, the stock Claude Code config for the official GitHub MCP server:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-github"]
    }
  }
}
```

becomes:

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

That is the only change required. Gateward spawns the server as a subprocess, forwards MCP traffic byte-for-byte in both directions, and records every message to `~/.gateward/audit.db`. The agent does not need to know Gateward is there. Override the DB path with the `GATEWARD_DB_PATH` environment variable if you want it elsewhere.

## What it blocks

Gateward enforces a set of hard-coded rules. Any blocked message is replaced with a JSON-RPC error response (`code: -32000`) so the agent sees a clean failure instead of a hang.

**Cross-repository access.** The first time the session calls a GitHub or GitLab MCP tool with a repo argument, Gateward records that repository. Any subsequent tool call targeting a different repository is blocked. This contains blast radius if an agent is tricked — by a poisoned issue, ticket, or retrieved document — into touching a repo the user never intended to expose.

**Prompt-injection phrases in tool responses.** Tool responses are the attack surface: an adversary who controls the content of a GitHub issue, Jira ticket, web page, or file can seed text that hijacks the agent. Gateward scans every tool response for a curated list of known injection phrases ("ignore previous instructions", "jailbreak", "reveal your instructions", and others) and blocks the response before it reaches the model. The matched phrase itself is never forwarded — only a generic error.

**Destructive shell and database commands.** Tool-call arguments are scanned for patterns that almost always indicate accidental or adversarial destruction — `rm -rf`, `DROP TABLE`, `DROP DATABASE`, unqualified `DELETE FROM` (no `WHERE` clause), `TRUNCATE TABLE`, `git push --force`, `git reset --hard`, `mkfs`, fork bombs, writes to `/dev/sda`, `chmod -R 777 /`, and similar. These are blocked at the proxy before they reach the server tool runner.

**Secrets in tool responses.** Tool responses are scanned for credential patterns — OpenAI API keys (`sk-...`), GitHub tokens (`ghp_`, `gho_`, `github_pat_`), AWS access keys (`AKIA...`), SSH and PGP private keys, JWTs, Slack tokens, bearer tokens, and connection strings for Postgres/MongoDB/MySQL/Redis. If an MCP server's response would leak a credential to the agent, Gateward blocks it before the model sees it.

**Path traversal and sandbox escape.** Tool-call arguments are scanned for path traversal sequences (`../../`, URL-encoded variants, Windows-style) and references to sensitive files (`/etc/passwd`, `/etc/shadow`, `~/.ssh/`, `~/.aws/`, `~/.gnupg/`, `/proc/self/environ`, `.env` files, SSH private keys like `id_rsa`/`id_ed25519`, `.pem` files). Requests attempting to read outside the intended scope are blocked before they reach the MCP server.

## Tailing the audit log

```
gateward tail            # print current log and exit
gateward tail --follow   # stream new rows as they arrive
gateward tail --session <id>  # filter to one session
```

Each row is color-coded by decision: green `ALLOW`, red `BLOCK`, yellow `WARN` (framing errors and similar). The full JSON of each message lives in the `messages.message_json` column of the SQLite DB if you need to dig deeper with `sqlite3 ~/.gateward/audit.db`.

## Known limitations

- **Stdio transport only.** HTTP and SSE MCP transports are not proxied in v0.2.
- **Rules are hard-coded.** There is no config file, policy DSL, or rule-authoring API. Customisation requires editing `patterns.py` and `rules.py`.
- **No configuration beyond `GATEWARD_DB_PATH`.** No YAML, no TOML, no env vars for tuning behavior.
- **No alerting.** Blocks are visible via `gateward tail`; there is no webhook, email, or Slack path.
- **No UI.** CLI only. No web dashboard.
- **Linux and macOS only.** Windows is not supported.
- **Single user, no authentication.** The audit DB is a local file and has no access control beyond filesystem permissions.

## Manual smoke test

1. `pip install -e .`
2. In terminal A, start following the log: `gateward tail --follow`
3. In terminal B, drive the bundled fake server through the proxy:

   ```
   echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | \
     gateward run -- python tests/fake_mcp_server.py
   ```

   You should see one `initialize` row appear in terminal A with decision `ALLOW`.

4. To see a block in action, pipe a request that the fake server will answer with an injection phrase:

   ```
   ( echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
     echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inject_test","arguments":{}}}'
   ) | gateward run -- python tests/fake_mcp_server.py
   ```

   Terminal A will show one `ALLOW` (the initialize response) followed by a `BLOCK` with `reason: injection_phrase_detected`, and the client receives a JSON-RPC error instead of the poisoned tool result.

## License

Apache 2.0. See `LICENSE`.
