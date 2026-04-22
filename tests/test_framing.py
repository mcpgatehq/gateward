"""Round-trip and error-path tests for the newline-delimited JSON framer."""
from __future__ import annotations

import asyncio
import json

import pytest

from gateward.framing import FramingError, read_message, write_message


async def _pair_streams() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Build a StreamReader/StreamWriter pair connected by an in-memory pipe.

    Uses asyncio's BaseTransport/Protocol plumbing via a socket pair so the
    same code paths as real pipes exercise the framer.
    """
    loop = asyncio.get_running_loop()
    read_fd, write_fd = _os_pipe()
    reader = asyncio.StreamReader(limit=20 * 1024 * 1024, loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
    read_pipe = _fdopen_rb(read_fd)
    await loop.connect_read_pipe(lambda: protocol, read_pipe)

    write_pipe = _fdopen_wb(write_fd)
    transport, w_protocol = await loop.connect_write_pipe(
        lambda: asyncio.streams.FlowControlMixin(loop=loop), write_pipe
    )
    writer = asyncio.StreamWriter(transport, w_protocol, None, loop)
    return reader, writer


def _os_pipe():
    import os

    return os.pipe()


def _fdopen_rb(fd):
    import os

    return os.fdopen(fd, "rb", buffering=0)


def _fdopen_wb(fd):
    import os

    return os.fdopen(fd, "wb", buffering=0)


def test_round_trip_many_sizes():
    async def _run():
        reader, writer = await _pair_streams()
        messages = []
        for i in range(100):
            payload = {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {"name": "t", "arguments": {"x": "y" * (10 * (i + 1))}},
            }
            messages.append(payload)

        async def send_all():
            for m in messages:
                await write_message(writer, m)
            writer.close()

        async def recv_all():
            received = []
            for _ in messages:
                msg = await read_message(reader)
                assert msg is not None
                received.append(msg)
            assert await read_message(reader) is None
            return received

        send_task = asyncio.create_task(send_all())
        received = await recv_all()
        await send_task
        assert received == messages

    asyncio.run(_run())


def test_large_message_5mb():
    async def _run():
        reader, writer = await _pair_streams()
        huge = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "Z" * (5 * 1024 * 1024)}]}}

        async def send():
            await write_message(writer, huge)
            writer.close()

        send_task = asyncio.create_task(send())
        got = await read_message(reader)
        await send_task
        assert got == huge

    asyncio.run(_run())


def test_malformed_json_raises_framing_error():
    async def _run():
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=1024, loop=loop)
        reader.feed_data(b"this is not json\n")
        reader.feed_eof()
        with pytest.raises(FramingError):
            await read_message(reader)

    asyncio.run(_run())


def test_non_object_top_level_raises():
    async def _run():
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=1024, loop=loop)
        reader.feed_data(b"[1,2,3]\n")
        reader.feed_eof()
        with pytest.raises(FramingError):
            await read_message(reader)

    asyncio.run(_run())


def test_eof_returns_none():
    async def _run():
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=1024, loop=loop)
        reader.feed_eof()
        assert await read_message(reader) is None

    asyncio.run(_run())


def test_blank_lines_skipped():
    async def _run():
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=1024, loop=loop)
        reader.feed_data(b"\n\n" + json.dumps({"ok": True}).encode() + b"\n")
        reader.feed_eof()
        msg = await read_message(reader)
        assert msg == {"ok": True}
        assert await read_message(reader) is None

    asyncio.run(_run())
