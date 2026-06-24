import os
import sys
import json
import shutil
import argparse
import http.client
import tempfile
import threading
import time
import logging
import traceback
import tomllib
import tomli_w
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Annotated, TypedDict, NotRequired
from urllib.parse import urlparse
import glob

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import McpServer
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest
    from ida_pro_mcp.ida_mcp.discovery import is_pid_alive
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest
    from discovery import is_pid_alive

    sys.path.pop(0)  # Clean up

log = logging.getLogger("ida-pro-mcp")

IDA_HOST = "127.0.0.1"
IDA_PORT = 13337

# Dynamic instance discovery. This path/schema is the single canonical
# contract shared with the IDA plugin's discovery.py -- keep them in sync.
INSTANCES_DIR = os.path.join(os.path.expanduser("~"), ".ida-mcp", "instances")

# Selection state. ACTIVE_INSTANCE is the chosen port; ACTIVE_EXPLICIT is True
# only when chosen via ida_select_instance. An explicitly chosen instance is
# NEVER silently rerouted to a different binary if it goes offline (that would
# land renames/patches on the wrong IDB). Guarded by _STATE_LOCK so the value
# is coherent under any concurrent access (HTTP transport / SSE keepalive).
ACTIVE_INSTANCE: int | None = None
ACTIVE_EXPLICIT: bool = False
_STATE_LOCK = threading.RLock()
LEGACY_MODE = False  # True when --ida-rpc is explicitly provided

# Per-tool-call proxy timeout. Heavy decompiles / full analysis can exceed the
# old 30s and would otherwise surface to the agent as a dropped request.
PROXY_TIMEOUT = float(os.environ.get("IDA_MCP_PROXY_TIMEOUT", "180"))
# Bounded retries for the connection-refused window (IDA plugin restarting).
# Only connection-establishment failures are retried -- never a request that may
# have already reached IDA, so write tools cannot be double-applied.
PROXY_CONNECT_RETRIES = int(os.environ.get("IDA_MCP_PROXY_RETRIES", "2"))


class InstanceInfo(TypedDict):
    """Information about a registered IDA instance."""
    host: str
    port: int
    description: str
    idb_path: str | None
    input_file: str | None
    started_at: str
    pid: int
    online: NotRequired[bool]
    active: NotRequired[bool]


_ONLINE_CACHE: dict[int, tuple[float, bool]] = {}  # port -> (monotonic_ts, online)
_ONLINE_CACHE_TTL = 3.0  # seconds


def check_instance_online(host: str, port: int) -> bool:
    """Check if IDA instance is responding."""
    try:
        conn = http.client.HTTPConnection(host, port, timeout=1)
        conn.request("POST", "/mcp", '{"jsonrpc":"2.0","method":"ping","id":1}',
                     {"Content-Type": "application/json"})
        response = conn.getresponse()
        conn.close()
        return response.status == 200
    except Exception:
        return False


def check_instance_online_cached(host: str, port: int) -> bool:
    """Cached online check -- avoids re-pinging on every tool call."""
    now = time.monotonic()
    cached = _ONLINE_CACHE.get(port)
    if cached and (now - cached[0]) < _ONLINE_CACHE_TTL:
        return cached[1]
    online = check_instance_online(host, port)
    _ONLINE_CACHE[port] = (now, online)
    return online


def _normalize_description(info: InstanceInfo, port: int) -> None:
    """Ensure a usable label exists regardless of which plugin version wrote
    the file (older writes ``description``, the unified schema writes both)."""
    if not info.get("description"):
        info["description"] = (
            info.get("binary")  # type: ignore[typeddict-item]
            or os.path.basename(info.get("idb_path") or "")
            or f"instance:{port}"
        )


def _read_registry() -> dict[int, InstanceInfo]:
    """Read instance files from ~/.ida-mcp/instances/, dropping dead-PID ghosts.

    Pure filesystem work -- NO network pings -- so it is always fast and bounded
    regardless of how many stale entries are present. Files whose owning process
    is gone are deleted here (and evicted from the online cache) so they stop
    inflating every later ping fan-out.
    """
    instances: dict[int, InstanceInfo] = {}
    if not os.path.exists(INSTANCES_DIR):
        return instances

    for filename in os.listdir(INSTANCES_DIR):
        if not filename.endswith(".json") or filename.startswith("."):
            continue
        filepath = os.path.join(INSTANCES_DIR, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                info: InstanceInfo = json.load(f)
            port = int(info["port"])
        except (json.JSONDecodeError, KeyError, ValueError, TypeError, IOError):
            continue

        pid = info.get("pid")
        if isinstance(pid, int) and not is_pid_alive(pid):
            try:
                os.unlink(filepath)
            except OSError:
                pass
            with _STATE_LOCK:
                _ONLINE_CACHE.pop(port, None)
            log.info(
                "discovery: removed stale instance port=%s pid=%s (%s)",
                port, pid, info.get("description"),
            )
            continue

        _normalize_description(info, port)
        instances[port] = info

    return instances


def discover_instances() -> dict[int, InstanceInfo]:
    """Registry read + online status. Pings are cached (3s TTL) and executed in
    parallel on cache miss so the STDIO loop is never blocked for N seconds."""
    instances = _read_registry()
    if not instances:
        return instances

    now = time.monotonic()
    needs_ping: list[tuple[int, InstanceInfo]] = []
    with _STATE_LOCK:
        for port, info in instances.items():
            cached = _ONLINE_CACHE.get(port)
            if cached and (now - cached[0]) < _ONLINE_CACHE_TTL:
                info["online"] = cached[1]
            else:
                needs_ping.append((port, info))

    if needs_ping:
        with ThreadPoolExecutor(max_workers=len(needs_ping)) as pool:
            futures = {
                pool.submit(check_instance_online, info["host"], port): (port, info)
                for port, info in needs_ping
            }
            for future in as_completed(futures):
                port, info = futures[future]
                try:
                    online = future.result()
                except Exception:
                    online = False
                with _STATE_LOCK:
                    _ONLINE_CACHE[port] = (time.monotonic(), online)
                info["online"] = online

    return instances


def get_target_instance() -> tuple[str, int] | None:
    """Resolve the instance to route a request to.

    Returns None when there is no usable target. Crucially, an *explicitly*
    selected instance that has gone offline returns None rather than silently
    rerouting to a different binary -- see _no_target_error_message for why.
    """
    global ACTIVE_INSTANCE

    if LEGACY_MODE:
        return (IDA_HOST, IDA_PORT)

    instances = discover_instances()
    if not instances:
        return None

    with _STATE_LOCK:
        active = ACTIVE_INSTANCE
        explicit = ACTIVE_EXPLICIT

    if active and active in instances and instances[active].get("online", False):
        return (instances[active]["host"], active)

    # Explicitly selected but unavailable: do NOT rebind to another binary.
    if explicit:
        return None

    # Auto mode only: fall back to the first online instance.
    for port, info in sorted(instances.items()):
        if info.get("online", False):
            with _STATE_LOCK:
                ACTIVE_INSTANCE = port
            return (info["host"], port)

    return None


def _no_target_error_message() -> str:
    """Human-readable reason there is no routable instance, distinguishing an
    explicit-but-offline selection (data-safety guard) from 'nothing running'."""
    shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
    with _STATE_LOCK:
        active = ACTIVE_INSTANCE
        explicit = ACTIVE_EXPLICIT
    if explicit and active:
        info = _read_registry().get(active)
        if info is None:
            return (
                f"The selected IDA instance on port {active} is no longer registered "
                f"(the IDB was likely closed). Use ida_list_instances then "
                f"ida_select_instance to choose another."
            )
        return (
            f"The selected IDA instance '{info.get('description')}' on port {active} "
            f"is offline. Because it was explicitly selected, requests are NOT "
            f"auto-routed to a different binary (that would corrupt the wrong IDB). "
            f"Restart that IDA's MCP server, or use ida_select_instance to switch."
        )
    return (
        f"No IDA instances available. Open IDA and press {shortcut} to start the "
        f"MCP server."
    )


def _instances_brief(instances: dict[int, InstanceInfo]) -> str:
    """Compact 'port (description) [online]' listing for error messages."""
    parts = []
    for port, info in sorted(instances.items()):
        state = "online" if info.get("online", False) else "offline"
        parts.append(f"{port} ({info.get('description')}) [{state}]")
    return ", ".join(parts) if parts else "(none)"


def resolve_instance(spec) -> tuple[tuple[str, int] | None, str | None]:
    """Resolve a PER-CALL instance spec to a (host, port) target.

    `spec` may be a port (int or numeric string) or a case-insensitive
    description/binary substring (e.g. "s21"). Returns ((host, port), None) on
    success, or (None, error_message). Does NOT mutate ACTIVE_INSTANCE -- routing
    is per request, so concurrent agents never clobber each other's selection.
    """
    instances = discover_instances()
    if not instances:
        return None, _no_target_error_message()

    port: int | None = None
    if isinstance(spec, bool):  # guard: bool is an int subclass
        return None, f"Invalid instance specifier: {spec!r}"
    if isinstance(spec, int):
        port = spec
    elif isinstance(spec, str) and spec.strip().isdigit():
        port = int(spec.strip())

    if port is not None:
        info = instances.get(port)
        if info is None:
            return None, f"No IDA instance registered on port {port}. Available: {_instances_brief(instances)}"
        if not info.get("online", False):
            return None, f"IDA instance on port {port} ('{info.get('description')}') is offline. Available: {_instances_brief(instances)}"
        return (info["host"], port), None

    needle = str(spec).strip().lower()
    if not needle:
        return None, "Empty instance specifier."
    matches = [
        (p, i)
        for p, i in instances.items()
        if i.get("online", False)
        and (needle in (i.get("description") or "").lower()
             or needle in (i.get("binary") or "").lower())
    ]
    if not matches:
        return None, f"No online IDA instance matches '{spec}'. Available: {_instances_brief(instances)}"
    if len(matches) > 1:
        cand = ", ".join(f"{p} ({i.get('description')})" for p, i in sorted(matches))
        return None, f"Instance '{spec}' is ambiguous -- matches: {cand}. Use a port number or a more specific substring."
    p, i = matches[0]
    return (i["host"], p), None


# Optional per-call routing field injected into every proxied tool's schema so
# an agent can target an instance inline instead of calling ida_select_instance.
INSTANCE_SCHEMA_PROP = {
    "type": "string",
    "description": (
        "Optional: target IDA instance for THIS call -- a port number "
        "(e.g. '13338') or a description/binary substring (e.g. 's21'). "
        "Omit to use the selected/auto instance. Use ida_list_instances to see options."
    ),
}


mcp = McpServer("ida-pro-mcp")


# Instance management tools (handled locally, not proxied to IDA)
@mcp.tool
def ida_list_instances() -> list[InstanceInfo]:
    """List all registered IDA instances with their status.
    Returns instances with description, port, idb_path, and online status.
    Use ida_select_instance to switch between instances."""
    instances = discover_instances()
    result: list[InstanceInfo] = []

    if not instances:
        return result

    with _STATE_LOCK:
        active = ACTIVE_INSTANCE

    first_online_port = None
    for port, info in sorted(instances.items()):
        if info.get("online", False) and first_online_port is None:
            first_online_port = port

    for port, info in sorted(instances.items()):
        # Mark as active if explicitly selected or auto-selected (first online)
        if active is not None:
            info["active"] = (port == active)
        else:
            info["active"] = (port == first_online_port)
        result.append(info)
    return result


@mcp.tool
def ida_select_instance(
    port: Annotated[int, "Port number of the IDA instance to select"]
) -> dict:
    """Select which IDA instance to use for subsequent tool calls.
    Use ida_list_instances first to see available instances."""
    global ACTIVE_INSTANCE, ACTIVE_EXPLICIT

    # Bounded: read the registry (filesystem only) and probe ONLY the requested
    # port. We never fan-out ping every (possibly dead) instance here, so this
    # tool cannot hang on N stale entries.
    instances = _read_registry()

    if port not in instances:
        return {
            "error": f"Instance on port {port} not found",
            "available_ports": sorted(instances.keys()),
        }

    info = instances[port]
    online = check_instance_online(info["host"], port)
    with _STATE_LOCK:
        _ONLINE_CACHE[port] = (time.monotonic(), online)

    if not online:
        return {
            "error": f"Instance on port {port} is offline",
            "description": info.get("description", "Unknown"),
        }

    with _STATE_LOCK:
        ACTIVE_INSTANCE = port
        ACTIVE_EXPLICIT = True
    log.info("select_instance: port=%s desc=%s", port, info.get("description"))
    return {
        "success": True,
        "port": port,
        "description": info.get("description", "Unknown"),
        "idb_path": info.get("idb_path"),
    }


@mcp.tool
def ida_get_active_instance() -> dict:
    """Get information about the currently active IDA instance."""
    instances = discover_instances()

    if not instances:
        return {"error": _no_target_error_message()}

    with _STATE_LOCK:
        active = ACTIVE_INSTANCE
        explicit = ACTIVE_EXPLICIT

    if active and active in instances:
        port = active
    elif explicit:
        # Explicitly selected instance is gone/offline -- report, do not rebind.
        return {"error": _no_target_error_message()}
    else:
        # Auto-select first online instance
        port = None
        for p, info in sorted(instances.items()):
            if info.get("online", False):
                port = p
                break
        if port is None:
            return {"error": _no_target_error_message()}

    info = instances[port]
    return {
        "port": port,
        "host": info.get("host", "127.0.0.1"),
        "description": info.get("description", "Unknown"),
        "idb_path": info.get("idb_path"),
        "input_file": info.get("input_file"),
        "online": info.get("online", False),
        "explicit": explicit and port == active,
    }


# List of local management tool names
LOCAL_TOOLS = {"ida_list_instances", "ida_select_instance", "ida_get_active_instance"}

dispatch_original = mcp.registry.dispatch


def proxy_to_ida(request: dict | str | bytes, host: str, port: int, inject_instance_info: bool = False) -> JsonRpcResponse | None:
    """Proxy a request to an IDA instance.

    Uses PROXY_TIMEOUT (default 180s, env-overridable) so heavy decompiles /
    full analysis are not dropped as the old 30s would. Retries ONLY on
    ConnectionRefusedError -- that is raised at connect time, before any bytes
    are sent, so a write tool (rename/set_type/patch) can never be re-applied.

    If inject_instance_info is True, instance metadata is added to the response
    so the model knows which binary it queried.
    """
    if isinstance(request, dict):
        body = json.dumps(request).encode("utf-8")
    elif isinstance(request, str):
        body = request.encode("utf-8")
    else:
        body = bytes(request)

    last_exc: Exception | None = None
    for attempt in range(PROXY_CONNECT_RETRIES + 1):
        conn = http.client.HTTPConnection(host, port, timeout=PROXY_TIMEOUT)
        try:
            # Enable extensions via query param (debugger tools enabled)
            conn.request("POST", "/mcp?ext=dbg", body, {"Content-Type": "application/json"})
            response = conn.getresponse()
            data = response.read().decode()
            result = json.loads(data)

            # Inject instance info into structuredContent (where Claude reads from)
            if inject_instance_info and "result" in result:
                mcp_result = result["result"]
                structured = mcp_result.get("structuredContent") if isinstance(mcp_result, dict) else None

                if structured is not None:
                    instances = _read_registry()
                    instance_info = instances.get(port)

                    if instance_info:
                        instance_meta = {
                            "port": port,
                            "description": instance_info.get("description"),
                            "idb_path": instance_info.get("idb_path"),
                        }
                    else:
                        instance_meta = {
                            "port": port,
                            "error": "instance not found in registry",
                            "available_ports": sorted(instances.keys()),
                        }

                    # Inject into structuredContent
                    if isinstance(structured, dict):
                        structured["_instance"] = instance_meta
                    elif isinstance(structured, list):
                        mcp_result["structuredContent"] = {"_instance": instance_meta, "data": structured}

            return result
        except ConnectionRefusedError as e:
            # Pre-send failure (plugin briefly down / restarting). Safe to retry.
            last_exc = e
            if attempt < PROXY_CONNECT_RETRIES:
                log.warning(
                    "proxy: connection refused %s:%s (attempt %d/%d), retrying",
                    host, port, attempt + 1, PROXY_CONNECT_RETRIES,
                )
                time.sleep(0.25 * (attempt + 1))
                continue
            raise
        finally:
            conn.close()

    if last_exc is not None:  # pragma: no cover - loop always returns or raises
        raise last_exc
    return None


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests to the MCP server registry or IDA instance."""
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore

    method = request_obj["method"]
    request_id = request_obj.get("id")

    # Handle MCP protocol methods locally
    if method == "initialize":
        return dispatch_original(request)
    elif method.startswith("notifications/"):
        return dispatch_original(request)

    # Handle tools/list: merge local tools with IDA tools
    if method == "tools/list":
        # Get local tools first
        local_response = dispatch_original(request)
        local_tools = local_response.get("result", {}).get("tools", []) if local_response else []

        # Try to get IDA tools
        target = get_target_instance()
        if target:
            try:
                ida_response = proxy_to_ida(request, target[0], target[1])
                ida_tools = ida_response.get("result", {}).get("tools", []) if ida_response else []
                # Advertise the optional per-call `instance` routing field on every
                # proxied tool so agents can target an instance inline.
                for t in ida_tools:
                    schema = t.get("inputSchema")
                    if isinstance(schema, dict):
                        props = schema.setdefault("properties", {})
                        if isinstance(props, dict):
                            props.setdefault("instance", INSTANCE_SCHEMA_PROP)
                # Merge: local tools first, then IDA tools
                all_tools = local_tools + ida_tools
                return {"jsonrpc": "2.0", "result": {"tools": all_tools}, "id": request_id}
            except Exception:
                pass  # Fall through to return just local tools

        return {"jsonrpc": "2.0", "result": {"tools": local_tools}, "id": request_id}

    # Handle tools/call: check if it's a local tool
    if method == "tools/call":
        params = request_obj.get("params", {})
        tool_name = params.get("name", "")

        # Strip the proxy-only `instance` routing field before the request ever
        # reaches a tool (local or IDA) -- the underlying tools don't accept it.
        args = params.get("arguments")
        inst_spec = args.pop("instance", None) if isinstance(args, dict) else None

        if tool_name in LOCAL_TOOLS:
            return dispatch_original(request_obj)

        # Per-call routing: an inline `instance` overrides the selected/auto target
        # for THIS request only (no ACTIVE_INSTANCE mutation -> multi-agent safe).
        if inst_spec not in (None, ""):
            target, err = resolve_instance(inst_spec)
            if target is None:
                if request_id is None:
                    return None
                return JsonRpcResponse({
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": err},
                    "id": request_id,
                })
        else:
            target = get_target_instance()
            if target is None:
                if request_id is None:
                    return None
                return JsonRpcResponse({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": _no_target_error_message(),
                    },
                    "id": request_id,
                })

        try:
            return proxy_to_ida(request_obj, target[0], target[1], inject_instance_info=True)
        except Exception as e:
            if request_id is None:
                return None
            shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
            return JsonRpcResponse({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": f"Failed to connect to IDA Pro on port {target[1]}! Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?\n{traceback.format_exc()}",
                    "data": str(e),
                },
                "id": request_id,
            })

    # All other methods: proxy to IDA
    target = get_target_instance()
    if target is None:
        if request_id is None:
            return None
        return JsonRpcResponse({
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": _no_target_error_message(),
            },
            "id": request_id,
        })

    try:
        return proxy_to_ida(request, target[0], target[1])
    except Exception as e:
        if request_id is None:
            return None
        shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
        return JsonRpcResponse({
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": f"Failed to connect to IDA Pro on port {target[1]}! Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?\n{traceback.format_exc()}",
                "data": str(e),
            },
            "id": request_id,
        })


mcp.registry.dispatch = dispatch_proxy


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_PLUGIN_PKG = os.path.join(SCRIPT_DIR, "ida_mcp")
IDA_PLUGIN_LOADER = os.path.join(SCRIPT_DIR, "ida_mcp.py")

# NOTE: This is in the global scope on purpose
if not os.path.exists(IDA_PLUGIN_PKG):
    raise RuntimeError(
        f"IDA plugin package not found at {IDA_PLUGIN_PKG} (did you move it?)"
    )
if not os.path.exists(IDA_PLUGIN_LOADER):
    raise RuntimeError(
        f"IDA plugin loader not found at {IDA_PLUGIN_LOADER} (did you move it?)"
    )


def get_python_executable():
    """Get the path to the Python executable"""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")

        split = path.split(os.sep)
        if split[-1].endswith(".zip"):
            path = os.path.dirname(path)
            if sys.platform == "win32":
                python_executable = os.path.join(path, "python.exe")
            else:
                python_executable = os.path.join(path, "..", "bin", "python3")
            python_executable = os.path.abspath(python_executable)

            if os.path.exists(python_executable):
                return python_executable
    return sys.executable


def copy_python_env(env: dict[str, str]):
    # Reference: https://docs.python.org/3/using/cmdline.html#environment-variables
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    # MCP servers are run without inheriting the environment, so we need to forward
    # the environment variables that affect Python's dependency resolution by hand.
    # Issue: https://github.com/mrexodia/ida-pro-mcp/issues/111
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result


def generate_mcp_config(*, stdio: bool, dynamic: bool = True):
    if stdio:
        if dynamic:
            # Dynamic mode: no --ida-rpc, instances discovered automatically
            mcp_config = {
                "command": get_python_executable(),
                "args": [__file__],
            }
        else:
            # Legacy mode: fixed IDA RPC server
            mcp_config = {
                "command": get_python_executable(),
                "args": [
                    __file__,
                    "--ida-rpc",
                    f"http://{IDA_HOST}:{IDA_PORT}",
                ],
            }
        env = {}
        if copy_python_env(env):
            print("[WARNING] Custom Python environment variables detected")
            mcp_config["env"] = env
        return mcp_config
    else:
        return {"type": "http", "url": f"http://{IDA_HOST}:{IDA_PORT}/mcp"}


def print_mcp_config():
    print("[STDIO MCP CONFIGURATION - DYNAMIC MODE (RECOMMENDED)]")
    print("Instances are discovered automatically from ~/.ida-mcp/instances/")
    print(
        json.dumps(
            {"mcpServers": {mcp.name: generate_mcp_config(stdio=True, dynamic=True)}}, indent=2
        )
    )
    print("\n[STDIO MCP CONFIGURATION - LEGACY MODE]")
    print(f"Fixed connection to {IDA_HOST}:{IDA_PORT}")
    print(
        json.dumps(
            {"mcpServers": {mcp.name: generate_mcp_config(stdio=True, dynamic=False)}}, indent=2
        )
    )
    print("\n[HTTP MCP CONFIGURATION]")
    print(
        json.dumps(
            {"mcpServers": {mcp.name: generate_mcp_config(stdio=False)}}, indent=2
        )
    )


def install_mcp_servers(*, stdio: bool = False, uninstall=False, quiet=False):
    # Map client names to their JSON key paths for clients that don't use "mcpServers"
    # Format: client_name -> (top_level_key, nested_key)
    # None means use default "mcpServers" at top level
    special_json_structures = {
        "VS Code": ("mcp", "servers"),
        "Visual Studio 2022": (None, "servers"),  # servers at top level
    }

    if sys.platform == "win32":
        configs = {
            "Cline": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(os.getenv("APPDATA", ""), "Claude"),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Zed": (
                os.path.join(os.getenv("APPDATA", ""), "Zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "darwin":
        configs = {
            "Cline": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(
                    os.path.expanduser("~"), "Library", "Application Support", "Claude"
                ),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(
                    os.path.expanduser("~"), "Library", "Application Support", "Zed"
                ),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "BoltAI": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "BoltAI",
                ),
                "config.json",
            ),
            "Perplexity": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Perplexity",
                ),
                "mcp_config.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "linux":
        configs = {
            "Cline": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            # Claude not supported on Linux
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(os.path.expanduser("~"), ".config", "zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
        }
    else:
        print(f"Unsupported platform: {sys.platform}")
        return

    installed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        is_toml = config_file.endswith(".toml")

        if not os.path.exists(config_dir):
            action = "uninstall" if uninstall else "installation"
            if not quiet:
                print(f"Skipping {name} {action}\n  Config: {config_path} (not found)")
            continue

        # Read existing config
        if not os.path.exists(config_path):
            config = {}
        else:
            with open(
                config_path,
                "rb" if is_toml else "r",
                encoding=None if is_toml else "utf-8",
            ) as f:
                if is_toml:
                    data = f.read()
                    if len(data) == 0:
                        config = {}
                    else:
                        try:
                            config = tomllib.loads(data.decode("utf-8"))
                        except tomllib.TOMLDecodeError:
                            if not quiet:
                                print(
                                    f"Skipping {name} uninstall\n  Config: {config_path} (invalid TOML)"
                                )
                            continue
                else:
                    data = f.read().strip()
                    if len(data) == 0:
                        config = {}
                    else:
                        try:
                            config = json.loads(data)
                        except json.decoder.JSONDecodeError:
                            if not quiet:
                                print(
                                    f"Skipping {name} uninstall\n  Config: {config_path} (invalid JSON)"
                                )
                            continue

        # Handle TOML vs JSON structure
        if is_toml:
            if "mcp_servers" not in config:
                config["mcp_servers"] = {}
            mcp_servers = config["mcp_servers"]
        else:
            # Check if this client uses a special JSON structure
            if name in special_json_structures:
                top_key, nested_key = special_json_structures[name]
                if top_key is None:
                    # servers at top level (e.g., Visual Studio 2022)
                    if nested_key not in config:
                        config[nested_key] = {}
                    mcp_servers = config[nested_key]
                else:
                    # nested structure (e.g., VS Code uses mcp.servers)
                    if top_key not in config:
                        config[top_key] = {}
                    if nested_key not in config[top_key]:
                        config[top_key][nested_key] = {}
                    mcp_servers = config[top_key][nested_key]
            else:
                # Default: mcpServers at top level
                if "mcpServers" not in config:
                    config["mcpServers"] = {}
                mcp_servers = config["mcpServers"]

        # Migrate old name
        old_name = "github.com/mrexodia/ida-pro-mcp"
        if old_name in mcp_servers:
            mcp_servers[mcp.name] = mcp_servers[old_name]
            del mcp_servers[old_name]

        if uninstall:
            if mcp.name not in mcp_servers:
                if not quiet:
                    print(
                        f"Skipping {name} uninstall\n  Config: {config_path} (not installed)"
                    )
                continue
            del mcp_servers[mcp.name]
        else:
            mcp_servers[mcp.name] = generate_mcp_config(stdio=stdio)

        # Atomic write: temp file + rename
        suffix = ".toml" if is_toml else ".json"
        fd, temp_path = tempfile.mkstemp(
            dir=config_dir, prefix=".tmp_", suffix=suffix, text=True
        )
        try:
            with os.fdopen(
                fd, "wb" if is_toml else "w", encoding=None if is_toml else "utf-8"
            ) as f:
                if is_toml:
                    f.write(tomli_w.dumps(config).encode("utf-8"))
                else:
                    json.dump(config, f, indent=2)
            os.replace(temp_path, config_path)
        except:
            os.unlink(temp_path)
            raise

        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(
                f"{action} {name} MCP server (restart required)\n  Config: {config_path}"
            )
        installed += 1
    if not uninstall and installed == 0:
        print(
            "No MCP servers installed. For unsupported MCP clients, use the following config:\n"
        )
        print_mcp_config()


def install_ida_plugin(
    *, uninstall: bool = False, quiet: bool = False, allow_ida_free: bool = False
):
    if sys.platform == "win32":
        ida_folder = os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
    else:
        ida_folder = os.path.join(os.path.expanduser("~"), ".idapro")
    if not allow_ida_free:
        free_licenses = glob.glob(os.path.join(ida_folder, "idafree_*.hexlic"))
        if len(free_licenses) > 0:
            print(
                "IDA Free does not support plugins and cannot be used. Purchase and install IDA Pro instead."
            )
            sys.exit(1)
    ida_plugin_folder = os.path.join(ida_folder, "plugins")

    # Install both the loader file and package directory
    loader_source = IDA_PLUGIN_LOADER
    loader_destination = os.path.join(ida_plugin_folder, "ida_mcp.py")

    pkg_source = IDA_PLUGIN_PKG
    pkg_destination = os.path.join(ida_plugin_folder, "ida_mcp")

    # Clean up old plugin if it exists
    old_plugin = os.path.join(ida_plugin_folder, "mcp-plugin.py")

    if uninstall:
        # Remove loader
        if os.path.lexists(loader_destination):
            os.remove(loader_destination)
            if not quiet:
                print(f"Uninstalled IDA plugin loader\n  Path: {loader_destination}")

        # Remove package
        if os.path.exists(pkg_destination):
            if os.path.isdir(pkg_destination) and not os.path.islink(pkg_destination):
                shutil.rmtree(pkg_destination)
            else:
                os.remove(pkg_destination)
            if not quiet:
                print(f"Uninstalled IDA plugin package\n  Path: {pkg_destination}")

        # Remove old plugin if it exists
        if os.path.lexists(old_plugin):
            os.remove(old_plugin)
            if not quiet:
                print(f"Removed old plugin\n  Path: {old_plugin}")
    else:
        # Create IDA plugins folder
        if not os.path.exists(ida_plugin_folder):
            os.makedirs(ida_plugin_folder)

        # Remove old plugin if it exists
        if os.path.lexists(old_plugin):
            os.remove(old_plugin)
            if not quiet:
                print(f"Removed old plugin file\n  Path: {old_plugin}")

        installed_items = []

        # Install loader file
        loader_realpath = (
            os.path.realpath(loader_destination)
            if os.path.lexists(loader_destination)
            else None
        )
        if loader_realpath != loader_source:
            if os.path.lexists(loader_destination):
                os.remove(loader_destination)

            try:
                os.symlink(loader_source, loader_destination)
                installed_items.append(f"loader: {loader_destination}")
            except OSError:
                shutil.copy(loader_source, loader_destination)
                installed_items.append(f"loader: {loader_destination}")

        # Install package directory
        pkg_realpath = (
            os.path.realpath(pkg_destination)
            if os.path.lexists(pkg_destination)
            else None
        )
        if pkg_realpath != pkg_source:
            if os.path.lexists(pkg_destination):
                if os.path.isdir(pkg_destination) and not os.path.islink(
                    pkg_destination
                ):
                    shutil.rmtree(pkg_destination)
                else:
                    os.remove(pkg_destination)

            try:
                os.symlink(pkg_source, pkg_destination)
                installed_items.append(f"package: {pkg_destination}")
            except OSError:
                shutil.copytree(pkg_source, pkg_destination)
                installed_items.append(f"package: {pkg_destination}")

        if not quiet:
            if installed_items:
                print("Installed IDA Pro plugin (IDA restart required)")
                for item in installed_items:
                    print(f"  {item}")
            else:
                print("Skipping IDA plugin installation (already up to date)")


def main():
    global IDA_HOST, IDA_PORT, LEGACY_MODE
    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install", action="store_true", help="Install the MCP Server and IDA plugin"
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Uninstall the MCP Server and IDA plugin",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        help="MCP transport protocol to use (stdio or http://127.0.0.1:8744)",
    )
    parser.add_argument(
        "--ida-rpc",
        type=str,
        default=None,
        help="IDA RPC server to use (omit for dynamic instance discovery)",
    )
    parser.add_argument(
        "--config", action="store_true", help="Generate MCP config JSON"
    )
    args = parser.parse_args()

    # Determine mode: legacy (fixed instance) or dynamic (auto-discovery)
    if args.ida_rpc is not None:
        # Legacy mode: use specified IDA RPC server
        LEGACY_MODE = True
        ida_rpc = urlparse(args.ida_rpc)
        if ida_rpc.hostname is None or ida_rpc.port is None:
            raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
        IDA_HOST = ida_rpc.hostname
        IDA_PORT = ida_rpc.port
    else:
        # Dynamic mode: discover instances from ~/.ida-mcp/instances/
        LEGACY_MODE = False

    if args.install and args.uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if args.install:
        install_ida_plugin(allow_ida_free=args.allow_ida_free)
        install_mcp_servers(stdio=(args.transport == "stdio"))
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True, allow_ida_free=args.allow_ida_free)
        install_mcp_servers(uninstall=True)
        return

    if args.config:
        print_mcp_config()
        return

    import logging
    _lifecycle_log = os.path.join(os.path.expanduser("~"), ".ida-mcp", "server_lifecycle.log")
    logging.basicConfig(
        filename=_lifecycle_log,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    logging.info("ida-pro-mcp server starting (transport=%s, legacy=%s, pid=%d)",
                 args.transport, LEGACY_MODE, os.getpid())

    try:
        if args.transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            mcp.serve(url.hostname, url.port)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        logging.info("server exiting cleanly (KeyboardInterrupt/EOF)")
    except Exception:
        logging.exception("server crashed with unhandled exception")
        raise
    finally:
        logging.info("server shutdown complete (pid=%d)", os.getpid())


if __name__ == "__main__":
    main()
