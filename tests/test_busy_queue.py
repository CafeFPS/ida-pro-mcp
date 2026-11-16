"""Proxy routing: a live busy IDA is not offline.

These tests do not need IDA. They exercise server.py discovery/routing
against a temp registry + sidecar.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from ida_pro_mcp import server

# server.py loads discovery as a top-level module (sys.path hack), then pops
# the path. Re-insert so this test can import it the same way.
import sys as _sys
_ida_mcp_dir = os.path.join(os.path.dirname(server.__file__), "ida_mcp")
if _ida_mcp_dir not in _sys.path:
    _sys.path.insert(0, _ida_mcp_dir)
import discovery


class BusyQueueRoutingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.inst_dir = os.path.join(self.tmp.name, "instances")
        self.status_dir = os.path.join(self.tmp.name, "status")
        os.makedirs(self.inst_dir)
        os.makedirs(self.status_dir)
        self.patchers = [
            patch.object(server, "INSTANCES_DIR", self.inst_dir),
            patch.object(server, "LEGACY_MODE", False),
            patch.object(server, "ACTIVE_INSTANCE", None),
            patch.object(server, "ACTIVE_EXPLICIT", False),
            patch.object(server, "PROXY_BUSY_CONNECT_WAIT", 0),
            patch.object(discovery, "get_instances_dir", lambda: self.inst_dir),
            patch.object(discovery, "get_status_dir", lambda: self.status_dir),
            patch.object(server, "is_pid_alive", lambda pid: True),
            patch.object(discovery, "is_pid_alive", lambda pid: True),
        ]
        for p in self.patchers:
            p.start()

    def tearDown(self):
        for p in reversed(self.patchers):
            p.stop()
        self.tmp.cleanup()

    def _write_instance(self, port=13338, pid=12345, desc="s21"):
        path = os.path.join(self.inst_dir, f"{port}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "host": "127.0.0.1",
                    "port": port,
                    "pid": pid,
                    "description": desc,
                    "binary": "r5apex.exe",
                    "idb_path": f"/tmp/{desc}.i64",
                    "started_at": "2026-01-01T00:00:00+00:00",
                },
                f,
            )
        return path

    def test_live_pid_is_routable_without_http_ping(self):
        self._write_instance()
        with patch.object(server, "check_instance_online", return_value=False):
            target = server.get_target_instance()
        self.assertEqual(target, ("127.0.0.1", 13338))

    def test_discover_marks_sidecar_busy_not_offline(self):
        self._write_instance()
        discovery.write_instance_status(
            13338,
            {
                "busy": True,
                "queue_depth": 1,
                "current": {"tool": "decompile", "elapsed_sec": 8.5},
                "queue": [{"tool": "find_bytes", "waited_sec": 2.0}],
            },
        )
        instances = server.discover_instances()
        info = instances[13338]
        self.assertTrue(info["online"])
        self.assertEqual(info["status"], "busy")
        self.assertTrue(info["busy"])
        self.assertEqual(info["current_tool"], "decompile")
        self.assertEqual(info["queue_depth"], 1)

    def test_busy_error_does_not_say_offline_or_start_plugin(self):
        self._write_instance(desc="s21 r5apex")
        discovery.write_instance_status(
            13338,
            {
                "busy": True,
                "queue_depth": 1,
                "current": {"tool": "find_regex", "elapsed_sec": 12.0},
                "queue": [{"tool": "decompile"}],
            },
        )
        msg = server._busy_message(13338)
        self.assertIn("busy, not down", msg)
        self.assertIn("find_regex", msg)
        self.assertNotIn("offline", msg.lower())
        self.assertNotIn("Edit -> Plugins", msg)

    def test_proxy_failure_live_pid_is_busy_not_connect_failed(self):
        self._write_instance()
        msg = server._proxy_failure_message(13338, TimeoutError("timed out"))
        self.assertIn("busy, not down", msg)
        self.assertNotIn("Edit -> Plugins", msg)

    def test_ida_queue_status_reads_sidecar(self):
        self._write_instance()
        discovery.write_instance_status(
            13338,
            {
                "busy": True,
                "queue_depth": 0,
                "current": {"tool": "xrefs_to", "elapsed_sec": 3.0},
                "queue": [],
            },
        )
        rows = server.ida_queue_status()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["port"], 13338)
        self.assertEqual(rows[0]["status"], "busy")
        self.assertEqual(rows[0]["current_tool"], "xrefs_to")

    def test_resolve_instance_accepts_busy_port(self):
        self._write_instance()
        discovery.write_instance_status(13338, {"busy": True, "queue_depth": 1})
        target, err = server.resolve_instance("13338")
        self.assertIsNone(err)
        self.assertEqual(target, ("127.0.0.1", 13338))

    def test_wait_for_tcp_skipped_when_timeout_zero(self):
        # Must not block or raise when connect_wait is 0.
        server._wait_for_tcp("127.0.0.1", 1, pid=os.getpid(), timeout=0)


if __name__ == "__main__":
    unittest.main()
