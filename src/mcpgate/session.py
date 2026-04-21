"""Per-proxy-run session state. State only — rules mutate it directly."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field


@dataclass
class Session:
    server_name: str
    server_command: str
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    first_repo_seen: str | None = None
    tool_call_count: int = 0
    blocked_count: int = 0
