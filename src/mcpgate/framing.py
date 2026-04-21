"""Newline-delimited JSON framing for MCP stdio transport.

MCP over stdio is line-delimited: one complete JSON object per line, each
terminated by a single ``\\n``. There is no Content-Length header — that is
the HTTP/LSP transport, which MCPGate does not implement in v0.1.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

# asyncio.StreamReader default limit is 64 KiB; real MCP messages can
# occasionally exceed that (large file reads, search results). Use 10 MiB.
MAX_MESSAGE_BYTES = 10 * 1024 * 1024


class FramingError(Exception):
    """Raised when a line cannot be parsed as JSON, or exceeds the size limit."""


async def read_message(stream: asyncio.StreamReader) -> dict[str, Any] | None:
    """Read one newline-delimited JSON message from ``stream``.

    Returns ``None`` at end of stream. Raises ``FramingError`` on malformed JSON
    or oversize lines. Skips empty keepalive lines silently.
    """
    while True:
        try:
            line = await stream.readline()
        except asyncio.LimitOverrunError as exc:
            # Drain the offending line so the stream stays usable, then raise.
            try:
                await stream.readexactly(exc.consumed)
            except (asyncio.IncompleteReadError, Exception):
                pass
            raise FramingError(f"line exceeds buffer limit: {exc}") from exc
        except ValueError as exc:
            raise FramingError(f"stream read failed: {exc}") from exc

        if not line:
            return None  # EOF

        stripped = line.rstrip(b"\r\n")
        if not stripped:
            # Empty line — some servers emit blank lines as keepalives. Skip.
            continue

        try:
            message = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise FramingError(f"invalid JSON: {exc.msg} at pos {exc.pos}") from exc

        if not isinstance(message, dict):
            raise FramingError(f"expected JSON object, got {type(message).__name__}")

        return message


async def write_message(stream: asyncio.StreamWriter, message: dict[str, Any]) -> None:
    """Serialize ``message`` as compact JSON + ``\\n`` and flush."""
    encoded = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    stream.write(encoded)
    stream.write(b"\n")
    await stream.drain()
