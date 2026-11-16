"""Tests for the in-process MCP tool queue tracker (no IDA required)."""

import os
import tempfile

from ..framework import test
from .. import discovery
from .. import queue_status


@test()
def test_queue_enter_mark_leave_snapshot():
    """enter queues, mark_running promotes, leave clears."""
    orig = discovery.get_status_dir
    with tempfile.TemporaryDirectory() as tmp:
        discovery.get_status_dir = lambda: tmp
        try:
            queue_status.unbind()
            queue_status.bind_port(13338)
            t1 = queue_status.enter("decompile")
            snap = queue_status.snapshot()
            assert snap["busy"] is True
            assert snap["in_flight"] == 1
            assert snap["current"]["tool"] == "decompile"

            queue_status.mark_running()
            snap = queue_status.snapshot()
            assert snap["current"]["state"] == "running"
            assert snap["current"]["tool"] == "decompile"

            t2 = queue_status.enter("find_bytes")
            snap = queue_status.snapshot()
            assert snap["in_flight"] == 2
            assert snap["queue_depth"] == 1
            assert snap["queue"][0]["tool"] == "find_bytes"

            queue_status.leave(t1)
            queue_status.leave(t2)
            snap = queue_status.snapshot()
            assert snap["busy"] is False
            assert snap["in_flight"] == 0
            assert snap["queue"] == []
        finally:
            queue_status.unbind()
            discovery.get_status_dir = orig


@test()
def test_queue_sidecar_written_on_enter():
    """enter() publishes a sidecar the proxy can read without talking to IDA."""
    orig = discovery.get_status_dir
    with tempfile.TemporaryDirectory() as tmp:
        discovery.get_status_dir = lambda: tmp
        try:
            queue_status.unbind()
            queue_status.bind_port(13339)
            queue_status.enter("xrefs_to")
            data = discovery.read_instance_status(13339)
            assert data is not None
            assert data["busy"] is True
            assert data["port"] == 13339
            tools = []
            if data.get("current"):
                tools.append(data["current"].get("tool"))
            tools.extend(q.get("tool") for q in data.get("queue") or [])
            assert "xrefs_to" in tools
        finally:
            queue_status.unbind()
            discovery.get_status_dir = orig
