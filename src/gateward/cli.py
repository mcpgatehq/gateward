"""Click entry point for Gateward."""
from __future__ import annotations

import asyncio
import time

import click
from rich.console import Console
from rich.text import Text

from gateward import __version__
from gateward.proxy import run_proxy
from gateward.storage import Storage, default_db_path


@click.group()
@click.version_option(version=__version__, prog_name="gateward")
def main() -> None:
    """Gateward — security gateway for MCP traffic."""


@main.command(
    context_settings=dict(ignore_unknown_options=True, allow_extra_args=True),
)
@click.argument("server_command", nargs=-1, required=True, type=click.UNPROCESSED)
def run(server_command: tuple[str, ...]) -> None:
    """Run the proxy. Example: gateward run -- npx @modelcontextprotocol/server-github"""
    storage = Storage(default_db_path())
    try:
        exit_code = asyncio.run(run_proxy(list(server_command), storage))
    finally:
        storage.close()
    raise SystemExit(exit_code)


@main.command()
@click.option("--follow", "-f", is_flag=True, help="Follow the log in real time.")
@click.option("--session", "session_id", default=None, help="Filter to a specific session ID.")
def tail(follow: bool, session_id: str | None) -> None:
    """Stream the audit log."""
    console = Console()
    storage = Storage(default_db_path())
    last_id = 0

    try:
        while True:
            rows = storage.tail(last_id=last_id)
            for row in rows:
                last_id = row["id"]
                if session_id and row["session_id"] != session_id:
                    continue
                _print_row(console, row)
            if not follow:
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        storage.close()


def _print_row(console: Console, row: dict) -> None:
    color = {"allow": "green", "block": "red", "warn": "yellow"}.get(row["decision"], "white")
    direction_arrow = "->" if row["direction"] == "client_to_server" else "<-"
    tool = row.get("tool_name") or row.get("method") or "?"
    text = Text()
    text.append(f"[{row['decision'].upper():5}] ", style=color)
    text.append(f"{direction_arrow} {tool}", style="white")
    if row["decision"] == "block" and row.get("decision_reason"):
        text.append(f"  reason: {row['decision_reason']}", style="red dim")
    console.print(text)
