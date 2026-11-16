"""In-flight MCP tool queue for one IDA plugin process.

HTTP threads call enter/leave around tools/call; the IDA main thread
calls mark_running once execute_sync starts the body. Snapshots are
written to ~/.ida-mcp/status/<port>.json so the stdio proxy can see the
queue even when this process is too busy to answer HTTP.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from .discovery import clear_instance_status, write_instance_status

_lock = threading.Lock()
_port: int | None = None
_items: list[dict[str, Any]] = []
_next_id = 1
_tls = threading.local()


def bind_port(port: int) -> None:
    global _port
    with _lock:
        _port = port
    _publish()


def unbind() -> None:
    global _port
    with _lock:
        port = _port
        _items.clear()
        _port = None
    if port is not None:
        clear_instance_status(port)


def enter(tool: str) -> int:
    global _next_id
    with _lock:
        ticket = _next_id
        _next_id += 1
        _items.append(
            {
                "id": ticket,
                "tool": tool,
                "queued_at": time.monotonic(),
                "started_at": None,
            }
        )
    _tls.ticket = ticket
    _publish()
    return ticket


def mark_running() -> None:
    ticket = getattr(_tls, "ticket", None)
    if ticket is None:
        return
    with _lock:
        for item in _items:
            if item["id"] == ticket and item["started_at"] is None:
                item["started_at"] = time.monotonic()
                break
        else:
            return
    _publish()


def leave(ticket: int | None = None) -> None:
    if ticket is None:
        ticket = getattr(_tls, "ticket", None)
    if ticket is None:
        return
    with _lock:
        _items[:] = [item for item in _items if item["id"] != ticket]
    if getattr(_tls, "ticket", None) == ticket:
        _tls.ticket = None
    _publish()


def snapshot() -> dict[str, Any]:
    now = time.monotonic()
    with _lock:
        items = [dict(item) for item in _items]
        port = _port

    current = None
    queued: list[dict[str, Any]] = []
    for item in items:
        waited = round(now - item["queued_at"], 2)
        if item["started_at"] is not None:
            current = {
                "tool": item["tool"],
                "elapsed_sec": round(now - item["started_at"], 2),
                "state": "running",
            }
        else:
            queued.append(
                {
                    "tool": item["tool"],
                    "waited_sec": waited,
                    "state": "queued",
                }
            )

    if current is None and items:
        oldest = items[0]
        current = {
            "tool": oldest["tool"],
            "elapsed_sec": round(now - oldest["queued_at"], 2),
            "state": "accepted",
        }
        queued = queued[1:] if queued else []

    return {
        "port": port,
        "busy": bool(items),
        "in_flight": len(items),
        "queue_depth": len(queued),
        "current": current,
        "queue": queued,
        "updated_at": time.time(),
    }


def _publish() -> None:
    port = _port
    if port is None:
        return
    try:
        write_instance_status(port, snapshot())
    except Exception:
        pass
