"""Stdio MCP proxy core.

``run_proxy`` spawns the downstream MCP server as a subprocess, wires parent
stdin/stdout to it, and runs two concurrent forwarder tasks. Every forwarded
message passes through ``rules.evaluate`` and is written to the audit log.
Blocks are surfaced to the client as synthesized JSON-RPC errors so the
agent never hangs on a silently dropped message.
"""
from __future__ import annotations

import asyncio
import os
import signal
import sys
import traceback
from typing import Any

from gateward.canary import CanaryTripwire
from gateward.framing import FramingError, read_message, write_message
from gateward.rules import Decision, evaluate
from gateward.schema_store import SchemaStore
from gateward.session import Session
from gateward.storage import Storage

_MAX_STREAM_BYTES = 10 * 1024 * 1024
_TERMINATE_GRACE_SECONDS = 2.0


def _derive_server_name(command: list[str]) -> str:
    """Pick a human-meaningful name from the server command.

    Uses the last non-flag argument, basenamed. This gets ``server-github``
    out of ``npx @modelcontextprotocol/server-github`` and ``fake_server.py``
    out of ``python path/to/fake_server.py`` — the package/script the user
    cares about, not the launcher.
    """
    candidates = [a for a in command if not a.startswith("-")]
    if not candidates:
        return " ".join(command) or "unknown"
    last = candidates[-1]
    base = os.path.basename(last) if "/" in last else last
    return base or " ".join(command)


def _synthesize_block_error(message_id: Any, rule: str) -> dict[str, Any]:
    """Build a JSON-RPC error response the client can understand.

    The rule name is exposed (e.g. ``injection_phrase``), but the specific
    matched phrase/pattern is not — that only goes to the audit log.
    """
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {
            "code": -32000,
            "message": f"Gateward blocked: {rule}",
        },
    }


def _log(
    storage: Storage,
    session: Session,
    direction: str,
    message: dict,
    decision: Decision,
) -> None:
    method = message.get("method")
    tool_name = None
    if method == "tools/call":
        params = message.get("params")
        if isinstance(params, dict):
            tool_name = params.get("name")
    try:
        storage.log_message(
            session.session_id,
            direction,
            message,
            method,
            tool_name,
            decision.action,
            decision.reason,
            session.server_name,
        )
    except Exception as exc:  # SQLite failure must not kill the proxy.
        print(f"gateward: storage failure: {exc}", file=sys.stderr)


def _safe_evaluate(message: dict, direction: str, session: Session) -> Decision:
    """Wrap evaluate() so a crashing rule fails open instead of killing the session."""
    try:
        return evaluate(message, direction, session)
    except Exception:
        traceback.print_exc()
        return Decision(action="allow", rule="none", reason="rule_eval_error")


async def _forward(
    *,
    reader: asyncio.StreamReader,
    forward_writer: asyncio.StreamWriter,
    client_writer: asyncio.StreamWriter,
    direction: str,
    session: Session,
    storage: Storage,
) -> None:
    """Read messages from ``reader`` and forward to ``forward_writer``.

    On block, write a synthesized error response to ``client_writer`` (which
    is the same as ``forward_writer`` for server-to-client traffic).
    """
    while True:
        try:
            message = await read_message(reader)
        except FramingError as exc:
            storage.log_message(
                session.session_id,
                direction,
                {"framing_error": str(exc)},
                None,
                None,
                "warn",
                f"framing_error: {exc}",
                session.server_name,
            )
            continue
        except (asyncio.CancelledError, GeneratorExit):
            raise
        except Exception as exc:
            print(f"gateward: read error ({direction}): {exc}", file=sys.stderr)
            break

        if message is None:
            break  # EOF

        if message.get("method") == "tools/call":
            session.tool_call_count += 1

        decision = _safe_evaluate(message, direction, session)
        _log(storage, session, direction, message, decision)

        if decision.action == "block":
            error_response = _synthesize_block_error(message.get("id"), decision.rule)
            try:
                await write_message(client_writer, error_response)
            except (ConnectionError, BrokenPipeError, OSError):
                return
            continue

        outbound_message = message
        if direction == "server_to_client" and session.canary_store is not None:
            # Rule 12 (inject side): stamp an invisible marker on every tool
            # response so the outbound checker can later catch the agent
            # copying response data into a new request. Failure is
            # non-fatal — if injection raises we still forward the original.
            try:
                outbound_message = session.canary_store.inject_into_response(
                    session.session_id, message
                )
            except Exception as exc:
                print(f"gateward: canary inject failed: {exc}", file=sys.stderr)
                outbound_message = message

        try:
            await write_message(forward_writer, outbound_message)
        except (ConnectionError, BrokenPipeError, OSError):
            return


async def run_proxy(server_command: list[str], storage: Storage) -> int:
    if not server_command:
        print("gateward: no server command provided", file=sys.stderr)
        return 2

    server_name = _derive_server_name(server_command)
    session = Session(server_name=server_name, server_command=" ".join(server_command))
    try:
        session.schema_store = SchemaStore()
    except Exception as exc:
        print(f"gateward: schema store init failed: {exc}", file=sys.stderr)
        session.schema_store = None
    session.canary_store = CanaryTripwire()
    storage.start_session(session.session_id, server_name, session.server_command)

    loop = asyncio.get_running_loop()

    # Wrap parent stdin as an async StreamReader.
    parent_stdin_reader = asyncio.StreamReader(limit=_MAX_STREAM_BYTES, loop=loop)
    stdin_protocol = asyncio.StreamReaderProtocol(parent_stdin_reader, loop=loop)
    stdin_pipe = os.fdopen(sys.stdin.fileno(), "rb", buffering=0, closefd=False)
    await loop.connect_read_pipe(lambda: stdin_protocol, stdin_pipe)

    # Wrap parent stdout as an async StreamWriter.
    stdout_pipe = os.fdopen(sys.stdout.fileno(), "wb", buffering=0, closefd=False)
    stdout_transport, stdout_protocol = await loop.connect_write_pipe(
        lambda: asyncio.streams.FlowControlMixin(loop=loop),
        stdout_pipe,
    )
    parent_stdout_writer = asyncio.StreamWriter(
        stdout_transport, stdout_protocol, reader=None, loop=loop
    )

    try:
        subprocess = await asyncio.create_subprocess_exec(
            *server_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,  # Inherit parent stderr so server errors surface.
            limit=_MAX_STREAM_BYTES,
        )
    except FileNotFoundError:
        print(
            f"gateward: command not found: {server_command[0]}",
            file=sys.stderr,
        )
        storage.end_session(session.session_id)
        return 127
    except OSError as exc:
        print(f"gateward: failed to spawn server: {exc}", file=sys.stderr)
        storage.end_session(session.session_id)
        return 1

    assert subprocess.stdin is not None
    assert subprocess.stdout is not None

    shutdown_event = asyncio.Event()

    def _request_shutdown() -> None:
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _request_shutdown)
        except (NotImplementedError, RuntimeError):
            # Signal handlers not available (e.g. non-main thread in tests).
            pass

    client_to_server = asyncio.create_task(
        _forward(
            reader=parent_stdin_reader,
            forward_writer=subprocess.stdin,
            client_writer=parent_stdout_writer,
            direction="client_to_server",
            session=session,
            storage=storage,
        ),
        name="gateward-c2s",
    )
    server_to_client = asyncio.create_task(
        _forward(
            reader=subprocess.stdout,
            forward_writer=parent_stdout_writer,
            client_writer=parent_stdout_writer,
            direction="server_to_client",
            session=session,
            storage=storage,
        ),
        name="gateward-s2c",
    )
    subprocess_wait = asyncio.create_task(subprocess.wait(), name="gateward-wait")
    shutdown_wait = asyncio.create_task(shutdown_event.wait(), name="gateward-shutdown")

    done, pending = await asyncio.wait(
        {client_to_server, server_to_client, subprocess_wait, shutdown_wait},
        return_when=asyncio.FIRST_COMPLETED,
    )

    # If the client went away first (EOF on parent stdin), signal the
    # subprocess by closing its stdin and give it a bounded chance to emit
    # any still-pending responses before we tear it down. This keeps
    # well-behaved servers from having their final messages dropped.
    if (
        client_to_server in done
        and shutdown_wait not in done
        and subprocess.returncode is None
    ):
        try:
            subprocess.stdin.close()
        except Exception:
            pass
        try:
            await asyncio.wait_for(
                asyncio.wait(
                    {server_to_client, subprocess_wait},
                    return_when=asyncio.ALL_COMPLETED,
                ),
                timeout=5.0,
            )
        except asyncio.TimeoutError:
            pass
        done = {t for t in (client_to_server, server_to_client, subprocess_wait, shutdown_wait) if t.done()}
        pending = {client_to_server, server_to_client, subprocess_wait, shutdown_wait} - done

    exit_code = 0
    if subprocess_wait in done:
        rc = subprocess_wait.result()
        if rc is not None and rc < 0:
            exit_code = 128 + (-rc)
        elif rc is not None:
            exit_code = rc

    # Tear down: cancel any remaining forwarders, terminate subprocess if alive.
    for task in pending:
        task.cancel()
    for task in pending:
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    if subprocess.returncode is None:
        # Give the child a brief chance to exit on its own (common after
        # stdin EOF) before we send SIGTERM — otherwise a normally-exiting
        # subprocess can be misattributed as signal-killed.
        try:
            await asyncio.wait_for(subprocess.wait(), timeout=0.5)
        except asyncio.TimeoutError:
            try:
                subprocess.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(subprocess.wait(), timeout=_TERMINATE_GRACE_SECONDS)
            except asyncio.TimeoutError:
                try:
                    subprocess.kill()
                except ProcessLookupError:
                    pass
                try:
                    await subprocess.wait()
                except Exception:
                    pass
        rc = subprocess.returncode
        # asyncio returns negative values for signal-killed processes; map
        # them to 128+signal so the caller sees a positive POSIX-ish code.
        if rc is None:
            exit_code = 0
        elif rc < 0:
            exit_code = 128 + (-rc)
        else:
            exit_code = rc

    # Remove signal handlers so later tests/reruns see a clean slate.
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.remove_signal_handler(sig)
        except (NotImplementedError, RuntimeError, ValueError):
            pass

    try:
        parent_stdout_writer.close()
    except Exception:
        pass

    storage.end_session(session.session_id)
    if session.schema_store is not None:
        session.schema_store.close()
    if session.canary_store is not None:
        session.canary_store.clear_session(session.session_id)
    return exit_code
