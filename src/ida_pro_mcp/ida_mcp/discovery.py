"""Instance discovery for IDA Pro MCP.

IDA plugin instances register themselves by writing JSON files to
~/.ida-mcp/instances/<port>.json. The MCP server (server.py) and the
plugin's own discovery tools both read this single canonical location,
validating PID liveness and (optionally) TCP reachability.

This path/schema MUST stay in lock-step with server.py's reader. Each
file carries both ``description`` (a human label that disambiguates IDBs
sharing a root filename, e.g. "r5apex.exe s3" vs "r5apex.exe s16") and
``binary`` (the raw root filename) so older and newer consumers agree.
"""

import datetime
import glob
import json
import os
import socket
import sys
import tempfile
from typing import NotRequired, TypedDict


class InstanceInfo(TypedDict):
    host: str
    port: int
    pid: int
    binary: str
    idb_path: str
    started_at: str
    description: NotRequired[str]
    input_file: NotRequired[str]


def get_instances_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".ida-mcp", "instances")


def _instance_file_path(port: int) -> str:
    return os.path.join(get_instances_dir(), f"{port}.json")


def register_instance(
    host: str,
    port: int,
    pid: int,
    binary: str,
    idb_path: str,
    description: str | None = None,
    input_file: str | None = None,
) -> str:
    """Write an instance registration file. Returns the file path."""
    info: InstanceInfo = {
        "host": host,
        "port": port,
        "pid": pid,
        "description": description or binary or os.path.basename(idb_path) or f"instance:{port}",
        "binary": binary,
        "idb_path": idb_path,
        "input_file": input_file or "",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    instances_dir = get_instances_dir()
    os.makedirs(instances_dir, exist_ok=True)
    file_path = _instance_file_path(port)
    # Atomic write
    fd, tmp_path = tempfile.mkstemp(dir=instances_dir, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2)
        os.replace(tmp_path, file_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return file_path


def unregister_instance(port: int) -> bool:
    """Remove an instance registration file. Returns True if removed."""
    file_path = _instance_file_path(port)
    try:
        os.unlink(file_path)
        return True
    except OSError:
        return False


def is_pid_alive(pid: int) -> bool:
    """Check if a process is still running."""
    if sys.platform == "win32":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            return True  # Process exists, we lack permission
        except ProcessLookupError:
            return False
        except OSError:
            return False


def probe_instance(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if an instance is reachable via TCP."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def discover_instances() -> list[InstanceInfo]:
    """Scan for registered instances, cleaning up stale entries."""
    instances_dir = get_instances_dir()
    if not os.path.isdir(instances_dir):
        return []

    result: list[InstanceInfo] = []
    pattern = os.path.join(instances_dir, "*.json")
    for file_path in glob.glob(pattern):
        # Skip in-flight atomic-write temp files (mkstemp prefix ".tmp_").
        # glob already excludes dotfiles, but guard explicitly for safety.
        if os.path.basename(file_path).startswith("."):
            continue
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                info: InstanceInfo = json.load(f)
        except (json.JSONDecodeError, OSError):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue

        if not all(k in info for k in ("host", "port", "pid")):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue

        if not is_pid_alive(info["pid"]):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue

        # Secondary check: verify the instance is actually listening.
        # Catches PID reuse (Windows can recycle PIDs quickly) and
        # cases where the process is alive but the server crashed.
        if not probe_instance(info["host"], info["port"], timeout=1.0):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue

        result.append(info)

    result.sort(key=lambda x: x.get("started_at", ""))
    return result
