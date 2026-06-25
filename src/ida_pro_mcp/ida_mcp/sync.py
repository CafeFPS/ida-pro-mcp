import logging
import queue
import functools
import os
import sys
import threading
import time
import idaapi
import ida_kernwin
import idc
from .rpc import McpToolError
from .zeromcp.jsonrpc import get_current_cancel_event, RequestCancelledError

# ============================================================================
# IDA Synchronization & Error Handling
# ============================================================================

ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))


class IDAError(McpToolError):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


class CancelledError(RequestCancelledError):
    """Raised when a request is cancelled via notifications/cancelled."""

    pass


logger = logging.getLogger(__name__)
_TOOL_TIMEOUT_ENV = "IDA_MCP_TOOL_TIMEOUT_SEC"
_DEFAULT_TOOL_TIMEOUT_SEC = 60.0


_deadline_state = threading.local()


def get_tool_deadline() -> float | None:
    """Return the monotonic deadline for the current tool call, or None.

    Only meaningful inside an @idasync function body. Tools that walk
    large structures can check `time.monotonic() >= get_tool_deadline()`
    to bail cleanly without depending on the global cancel flag.
    """
    return getattr(_deadline_state, "deadline", None)


def _get_tool_timeout_seconds() -> float:
    value = os.getenv(_TOOL_TIMEOUT_ENV, "").strip()
    if value == "":
        return _DEFAULT_TOOL_TIMEOUT_SEC
    try:
        return float(value)
    except ValueError:
        return _DEFAULT_TOOL_TIMEOUT_SEC


call_stack = queue.LifoQueue()

_sync_state = threading.local()


def get_pre_call_batch() -> int | None:
    """Return the pre-call batch state, or None if not inside a sync body."""
    return getattr(_sync_state, "pre_call_batch", None)


def _sync_wrapper(ff, keep_batch=False):
    """Call a function ff with a specific IDA safety_mode.

    If keep_batch=True and ff() returns successfully, batch mode is left on
    after the wrapper exits. The decorated function is responsible for
    arranging restoration (typically via a DBG_Hooks callback).
    """

    res_container = queue.Queue()

    def runned():
        if not call_stack.empty():
            try:
                last_func_name = call_stack.get_nowait()
            except queue.Empty:
                last_func_name = "<empty>"
            error_str = f"Call stack is not empty while calling the function {ff.__name__} from {last_func_name}"
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        old_batch = idc.batch(1)
        prev_pre_call = getattr(_sync_state, "pre_call_batch", None)
        _sync_state.pre_call_batch = old_batch
        completed = False
        try:
            res_container.put(ff())
            completed = True
        except Exception as x:
            res_container.put(x)
        finally:
            if not (completed and keep_batch):
                idc.batch(old_batch)
            _sync_state.pre_call_batch = prev_pre_call
            try:
                call_stack.get_nowait()
            except queue.Empty:
                pass

    idaapi.execute_sync(runned, idaapi.MFF_WRITE)
    res = res_container.get()
    if isinstance(res, Exception):
        raise res
    return res


def _normalize_timeout(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def sync_wrapper(
    ff, timeout_override: float | None = None, keep_batch: bool = False
):
    """Wrapper to enable timeout and cancellation during IDA synchronization.

    Note: Batch mode is now handled in _sync_wrapper to ensure it's always
    applied consistently for all synchronized operations. Pass keep_batch=True
    to opt out of the post-call batch restore (see _sync_wrapper docstring).
    """
    cancel_event = get_current_cancel_event()

    timeout = timeout_override
    if timeout is None:
        timeout = _get_tool_timeout_seconds()
    if timeout > 0 or cancel_event is not None:

        def timed_ff():
            deadline = time.monotonic() + timeout if timeout > 0 else None

            # Native cancellation: schedule set_cancelled() at deadline so
            # C-level IDA calls (find_text, bin_search, decompile, etc.)
            # that poll user_cancelled() bail within one poll cycle instead
            # of running to natural completion.
            ida_kernwin.clr_cancelled()
            cancel_fired_at: list[float | None] = [None]
            native_timer: threading.Timer | None = None
            if deadline is not None:
                def _fire_native_cancel():
                    cancel_fired_at[0] = time.monotonic()
                    ida_kernwin.set_cancelled()
                native_timer = threading.Timer(timeout, _fire_native_cancel)
                native_timer.daemon = True
                native_timer.start()

            def profilefunc(frame, event, arg):
                if cancel_event is not None and cancel_event.is_set():
                    raise CancelledError("Request was cancelled")
                fired_at = cancel_fired_at[0]
                if fired_at is not None and time.monotonic() < fired_at + 5.0:
                    return
                if deadline is not None and time.monotonic() >= deadline:
                    raise IDASyncError(f"Tool timed out after {timeout:.2f}s")

            _deadline_state.deadline = deadline
            old_profile = sys.getprofile()
            sys.setprofile(profilefunc)
            try:
                return ff()
            finally:
                sys.setprofile(old_profile)
                if native_timer is not None:
                    native_timer.cancel()
                ida_kernwin.clr_cancelled()
                _deadline_state.deadline = None

        timed_ff.__name__ = ff.__name__
        return _sync_wrapper(timed_ff, keep_batch=keep_batch)
    return _sync_wrapper(ff, keep_batch=keep_batch)


def idasync(f):
    """Run the function on the IDA main thread in write mode.

    This is the unified decorator for all IDA synchronization.
    Previously there were separate @idaread and @idawrite decorators,
    but since read-only operations in IDA might actually require write
    access (e.g., decompilation), we now use a single decorator.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(
            getattr(f, "__ida_mcp_timeout_sec__", None)
        )
        return sync_wrapper(ff, timeout_override)

    return wrapper


def tool_timeout(seconds: float):
    """Decorator to override per-tool timeout (seconds).

    IMPORTANT: Must be applied BEFORE @idasync (i.e., listed AFTER it)
    so the attribute exists when it captures the function in closure.

    Correct order:
        @tool
        @idasync
        @tool_timeout(90.0)  # innermost
        def my_func(...):
    """

    def decorator(func):
        setattr(func, "__ida_mcp_timeout_sec__", seconds)
        return func

    return decorator


def is_window_active():
    """Returns whether IDA is currently active."""
    # Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)

    if using_pyside6:
        from PySide6 import QtWidgets
    else:
        from PyQt5 import QtWidgets

    app = QtWidgets.QApplication.instance()
    if app is None:
        return False
    return app.activeWindow() is not None
