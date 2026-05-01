import os
import sys
import json
import shutil
import argparse
import http.client
import tempfile
import time
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
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest

    sys.path.pop(0)  # Clean up

IDA_HOST = "127.0.0.1"
IDA_PORT = 13337

# Dynamic instance discovery
INSTANCES_DIR = os.path.join(os.path.expanduser("~"), ".ida-mcp", "instances")
ACTIVE_INSTANCE: int | None = None  # Port number of active instance
LEGACY_MODE = False  # True when --ida-rpc is explicitly provided


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


def discover_instances() -> dict[int, InstanceInfo]:
    """Read all instance files from ~/.ida-mcp/instances/

    Pings are cached (3s TTL) and executed in parallel on cache miss
    to avoid blocking the STDIO event loop for N seconds with N instances.
    """
    instances: dict[int, InstanceInfo] = {}
    if not os.path.exists(INSTANCES_DIR):
        return instances

    # Phase 1: read all JSON files (fast, no I/O blocking)
    for filename in os.listdir(INSTANCES_DIR):
        if not filename.endswith(".json"):
            continue
        filepath = os.path.join(INSTANCES_DIR, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                info: InstanceInfo = json.load(f)
            port = info["port"]
            instances[port] = info
        except (json.JSONDecodeError, KeyError, IOError):
            continue

    if not instances:
        return instances

    # Phase 2: check online status (parallel, cached)
    now = time.monotonic()
    needs_ping: list[tuple[int, InstanceInfo]] = []
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
                _ONLINE_CACHE[port] = (time.monotonic(), online)
                info["online"] = online

    return instances


def get_target_instance() -> tuple[str, int] | None:
    """Get host and port of the instance to route requests to."""
    global ACTIVE_INSTANCE

    if LEGACY_MODE:
        return (IDA_HOST, IDA_PORT)

    instances = discover_instances()
    if not instances:
        return None

    # Use active instance if set and still exists and online
    if ACTIVE_INSTANCE and ACTIVE_INSTANCE in instances:
        info = instances[ACTIVE_INSTANCE]
        if info.get("online", False):
            return (info["host"], ACTIVE_INSTANCE)

    # Auto-select first online instance
    for port, info in sorted(instances.items()):
        if info.get("online", False):
            ACTIVE_INSTANCE = port
            return (info["host"], port)

    return None


mcp = McpServer("ida-pro-mcp")


# Instance management tools (handled locally, not proxied to IDA)
@mcp.tool
def ida_list_instances() -> list[InstanceInfo]:
    """List all registered IDA instances with their status.
    Returns instances with description, port, idb_path, and online status.
    Use ida_select_instance to switch between instances."""
    global ACTIVE_INSTANCE
    instances = discover_instances()
    result: list[InstanceInfo] = []

    if not instances:
        return result

    first_online_port = None
    for port, info in sorted(instances.items()):
        if info.get("online", False) and first_online_port is None:
            first_online_port = port

    for port, info in sorted(instances.items()):
        # Mark as active if explicitly selected or auto-selected (first online)
        if ACTIVE_INSTANCE is not None:
            info["active"] = (port == ACTIVE_INSTANCE)
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
    global ACTIVE_INSTANCE
    instances = discover_instances()

    if port not in instances:
        available = list(instances.keys())
        return {"error": f"Instance on port {port} not found", "available_ports": available}

    info = instances[port]
    if not info.get("online", False):
        return {
            "error": f"Instance on port {port} is offline",
            "description": info.get("description", "Unknown")
        }

    ACTIVE_INSTANCE = port
    return {
        "success": True,
        "port": port,
        "description": info.get("description", "Unknown"),
        "idb_path": info.get("idb_path")
    }


@mcp.tool
def ida_get_active_instance() -> dict:
    """Get information about the currently active IDA instance."""
    global ACTIVE_INSTANCE
    instances = discover_instances()

    if not instances:
        return {"error": "No IDA instances available. Open IDA and press Ctrl+Alt+M to start."}

    # Find active instance
    if ACTIVE_INSTANCE and ACTIVE_INSTANCE in instances:
        port = ACTIVE_INSTANCE
    else:
        # Auto-select first online instance
        port = None
        for p, info in sorted(instances.items()):
            if info.get("online", False):
                port = p
                break
        if port is None:
            return {"error": "No online IDA instances available"}

    info = instances[port]
    return {
        "port": port,
        "host": info.get("host", "127.0.0.1"),
        "description": info.get("description", "Unknown"),
        "idb_path": info.get("idb_path"),
        "input_file": info.get("input_file"),
        "online": info.get("online", False)
    }


# List of local management tool names
LOCAL_TOOLS = {"ida_list_instances", "ida_select_instance", "ida_get_active_instance"}

dispatch_original = mcp.registry.dispatch


def proxy_to_ida(request: dict | str | bytes, host: str, port: int, inject_instance_info: bool = False) -> JsonRpcResponse | None:
    """Proxy a request to IDA instance.

    If inject_instance_info is True, adds instance metadata to the response
    so the model knows which binary it queried.
    """
    conn = http.client.HTTPConnection(host, port, timeout=30)
    try:
        if isinstance(request, dict):
            request = json.dumps(request)
        elif isinstance(request, str):
            request = request.encode("utf-8")
        # Enable extensions via query param (debugger tools enabled)
        conn.request("POST", "/mcp?ext=dbg", request, {"Content-Type": "application/json"})
        response = conn.getresponse()
        data = response.read().decode()
        result = json.loads(data)

        # Inject instance info into structuredContent (where Claude reads from)
        if inject_instance_info and "result" in result:
            mcp_result = result["result"]
            structured = mcp_result.get("structuredContent") if isinstance(mcp_result, dict) else None

            if structured is not None:
                instances = discover_instances()
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
                        "available_ports": list(instances.keys()),
                    }

                # Inject into structuredContent
                if isinstance(structured, dict):
                    structured["_instance"] = instance_meta
                elif isinstance(structured, list):
                    mcp_result["structuredContent"] = {"_instance": instance_meta, "data": structured}

        return result
    finally:
        conn.close()


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

        if tool_name in LOCAL_TOOLS:
            return dispatch_original(request)

        # Proxy to IDA
        target = get_target_instance()
        if target is None:
            if request_id is None:
                return None
            shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
            return JsonRpcResponse({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": f"No IDA instances available. Open IDA and press {shortcut} to start the MCP server.",
                },
                "id": request_id,
            })

        try:
            return proxy_to_ida(request, target[0], target[1], inject_instance_info=True)
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
        shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
        return JsonRpcResponse({
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": f"No IDA instances available. Open IDA and press {shortcut} to start the MCP server.",
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
