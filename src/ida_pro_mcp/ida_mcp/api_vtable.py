"""Vtable / RTTI / C++ class-recovery tools.

MSVC emits each class vftable as a symbol named ``??_7<Class>@@6B@`` (and RTTI
Complete Object Locators as ``??_R4...``). These tools surface that structure
for deep C++ / Source-engine RE:

- ``list_rtti``        -- enumerate recovered vftables (demangled class + slot count)
- ``find_vtables``     -- find vftables for a class-name substring
- ``get_vtable``       -- dump a vftable's slots to their resolved functions
- ``xrefs_to_vtable``  -- who references a vftable (typically constructors)
- ``demangle``         -- demangle an MSVC/Itanium C++ symbol
- ``name_vtable_slot`` -- name the function behind vtable slot N (e.g. engVt[39])

Slot enumeration walks consecutive pointer-sized entries that point into an
executable segment, stopping at the next named location (the start of the next
vftable) -- so it does not bleed across class boundaries.
"""

from typing import Annotated, NotRequired, TypedDict

import ida_bytes
import ida_funcs
import ida_name
import idaapi
import idautils

from . import compat
from .rpc import tool
from .sync import idasync, IDAError
from .utils import Page, paginate, parse_address, pattern_filter

VFTABLE_PREFIX = "??_7"  # MSVC mangled vftable symbol
_MAX_SLOTS = 8192  # hard cap so a misidentified vtable can never run away


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _ptr_size() -> int:
    return 8 if compat.inf_is_64bit() else 4


def _read_ptr(ea: int) -> int:
    return ida_bytes.get_qword(ea) if _ptr_size() == 8 else ida_bytes.get_wide_dword(ea)


def _is_exec(ea: int) -> bool:
    seg = idaapi.getseg(ea)
    return bool(seg and (seg.perm & idaapi.SEGPERM_EXEC))


def _demangle(name: str | None) -> str | None:
    if not name:
        return None
    d = idaapi.demangle_name(name, idaapi.MNG_NODEFINIT)
    return d or None


def _class_from_vftable(demangled: str) -> str:
    """'const CBaseEntity::`vftable'{for ...}' -> 'CBaseEntity'."""
    if not demangled:
        return ""
    s = demangled
    if s.startswith("const "):
        s = s[6:]
    idx = s.find("::`vftable'")
    return s[:idx] if idx >= 0 else s


def _func_label(ea: int) -> str:
    return ida_funcs.get_func_name(ea) or ida_name.get_name(ea) or hex(ea)


def _slot_boundary(idx: int, slot_ea: int) -> bool:
    """A vftable ends where the next named location begins (idx 0 is the table
    symbol itself, so it is never a boundary)."""
    return idx > 0 and bool(ida_name.get_name(slot_ea))


def _count_slots(ea: int) -> int:
    ps = _ptr_size()
    n = 0
    a = ea
    while n < _MAX_SLOTS:
        if _slot_boundary(n, a):
            break
        if not _is_exec(_read_ptr(a)):
            break
        n += 1
        a += ps
    return n


def _enumerate_vftables() -> list[dict]:
    """All MSVC vftable symbols as lightweight records (no slot counting)."""
    out: list[dict] = []
    for ea, name in idautils.Names():
        if not name.startswith(VFTABLE_PREFIX):
            continue
        demangled = _demangle(name) or ""
        out.append(
            {
                "_ea": ea,
                "vtable_ea": hex(ea),
                "mangled": name,
                "demangled": demangled,
                "class_name": _class_from_vftable(demangled),
            }
        )
    return out


def _resolve_vtable_ea(target: str) -> int | None:
    """Resolve a vtable address / symbol / class-name substring to an address."""
    t = (target or "").strip()
    if not t:
        return None

    # Direct address or exact (mangled) symbol -- parse_address handles both.
    try:
        ea = parse_address(t)
        if ea != idaapi.BADADDR and ida_bytes.is_loaded(ea):
            return ea
    except Exception:
        pass

    # Class-name substring against recovered vftables.
    needle = t.lower()
    cands = [
        (rec["_ea"], rec["class_name"])
        for rec in _enumerate_vftables()
        if needle in rec["class_name"].lower()
    ]
    if len(cands) == 1:
        return cands[0][0]
    if len(cands) > 1:
        listing = ", ".join(f"{hex(e)} {c}" for e, c in cands[:20])
        raise IDAError(
            f"Vtable spec '{target}' is ambiguous -- matches: {listing}"
            f"{' ...' if len(cands) > 20 else ''}. Use an address or a more specific name."
        )
    return None


# ---------------------------------------------------------------------------
# Return shapes
# ---------------------------------------------------------------------------


class DemangleResult(TypedDict):
    input: str
    is_mangled: bool
    demangled: NotRequired[str]


class VtableInfo(TypedDict):
    vtable_ea: str
    mangled: str
    class_name: str
    demangled: str
    slot_count: int


class VtableSlot(TypedDict):
    index: int
    slot_ea: str
    func_ea: str
    name: str
    demangled: NotRequired[str]


class VtableDump(TypedDict):
    vtable_ea: str
    slot_count: int
    slots: list[VtableSlot]
    mangled: NotRequired[str]
    class_name: NotRequired[str]


class VtableXref(TypedDict):
    ea: str
    func_ea: NotRequired[str]
    func_name: NotRequired[str]


class NameSlotResult(TypedDict):
    vtable_ea: str
    index: int
    slot_ea: str
    func_ea: str
    old_name: str
    new_name: str
    success: bool


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@tool
@idasync
def demangle(
    name: Annotated[
        str,
        "A mangled C++ symbol (e.g. ??_7CBaseEntity@@6B@), or an address/name "
        "whose stored symbol should be looked up and demangled first.",
    ],
) -> DemangleResult:
    """Demangle an MSVC/Itanium C++ symbol to its human-readable form."""
    raw = (name or "").strip()
    target = raw
    try:
        ea = parse_address(raw)
        if ea != idaapi.BADADDR:
            nm = ida_name.get_name(ea)
            if nm:
                target = nm
    except Exception:
        pass
    d = _demangle(target)
    result: DemangleResult = {"input": target, "is_mangled": d is not None}
    if d:
        result["demangled"] = d
    return result


@tool
@idasync
def list_rtti(
    filter: Annotated[
        str, "Optional class-name substring or glob (e.g. 'CPlayer', '*Weapon*')"
    ] = "",
    offset: Annotated[int, "Skip first N results (default: 0)"] = 0,
    count: Annotated[int, "Max results (default: 100, 0 = all)"] = 100,
) -> Page[VtableInfo]:
    """List C++ vftables recovered from MSVC RTTI symbols (??_7<Class>@@6B@),
    with demangled class names and slot counts. Slot counts are computed only for
    the returned page, so this stays fast on large binaries."""
    items = _enumerate_vftables()
    if filter and filter not in ("", "*"):
        items = pattern_filter(items, filter, "class_name")
    page = paginate(items, offset, count)
    hydrated: list[VtableInfo] = []
    for rec in page["data"]:
        hydrated.append(
            {
                "vtable_ea": rec["vtable_ea"],
                "mangled": rec["mangled"],
                "class_name": rec["class_name"],
                "demangled": rec["demangled"],
                "slot_count": _count_slots(rec["_ea"]),
            }
        )
    page["data"] = hydrated
    return page


@tool
@idasync
def find_vtables(
    class_substr: Annotated[
        str, "Class-name substring to search for (case-insensitive, e.g. 'CClient')"
    ],
    offset: Annotated[int, "Skip first N results (default: 0)"] = 0,
    count: Annotated[int, "Max results (default: 100, 0 = all)"] = 100,
) -> Page[VtableInfo]:
    """Find vftables whose class name contains a substring. Convenience wrapper
    around list_rtti for class-targeted lookups."""
    return list_rtti(filter=class_substr, offset=offset, count=count)


@tool
@idasync
def get_vtable(
    target: Annotated[
        str,
        "Vtable address (hex like 0x14..), a (mangled) symbol, or a class-name "
        "substring (e.g. 'CBaseEntity') resolved against ??_7 vftables.",
    ],
    offset: Annotated[int, "Skip first N slots (default: 0)"] = 0,
    count: Annotated[int, "Max slots returned (default: 0 = all)"] = 0,
) -> VtableDump:
    """Dump a C++ vftable's slots to their target functions (names + demangled).
    slot_count is the full table length; slots honors offset/count."""
    ea = _resolve_vtable_ea(target)
    if ea is None:
        raise IDAError(
            f"Could not resolve a vtable for {target!r}. Use list_rtti / find_vtables to locate one."
        )

    ps = _ptr_size()
    all_slots: list[VtableSlot] = []
    a = ea
    idx = 0
    while idx < _MAX_SLOTS:
        if _slot_boundary(idx, a):
            break
        ptr = _read_ptr(a)
        if not _is_exec(ptr):
            break
        label = _func_label(ptr)
        slot: VtableSlot = {
            "index": idx,
            "slot_ea": hex(a),
            "func_ea": hex(ptr),
            "name": label,
        }
        d = _demangle(label)
        if d:
            slot["demangled"] = d
        all_slots.append(slot)
        idx += 1
        a += ps

    total = len(all_slots)
    if count:
        sliced = all_slots[offset : offset + count]
    elif offset:
        sliced = all_slots[offset:]
    else:
        sliced = all_slots

    name = ida_name.get_name(ea) or ""
    dump: VtableDump = {"vtable_ea": hex(ea), "slot_count": total, "slots": sliced}
    if name:
        dump["mangled"] = name
        cls = _class_from_vftable(_demangle(name) or "")
        if cls:
            dump["class_name"] = cls
    return dump


@tool
@idasync
def xrefs_to_vtable(
    target: Annotated[
        str, "Vtable address / symbol / class-name substring"
    ],
    offset: Annotated[int, "Skip first N results (default: 0)"] = 0,
    count: Annotated[int, "Max results (default: 200, 0 = all)"] = 200,
) -> Page[VtableXref]:
    """Find references to a vftable -- typically the constructors that install it
    into an object instance."""
    ea = _resolve_vtable_ea(target)
    if ea is None:
        raise IDAError(
            f"Could not resolve a vtable for {target!r}. Use list_rtti / find_vtables to locate one."
        )
    items: list[VtableXref] = []
    for xref in idautils.XrefsTo(ea):
        frm = xref.frm
        rec: VtableXref = {"ea": hex(frm)}
        fn = idaapi.get_func(frm)
        if fn:
            rec["func_ea"] = hex(fn.start_ea)
            rec["func_name"] = ida_funcs.get_func_name(fn.start_ea) or "<unnamed>"
        items.append(rec)
    return paginate(items, offset, count)


@tool
@idasync
def name_vtable_slot(
    vtable: Annotated[str, "Vtable address / symbol / class-name substring"],
    index: Annotated[int, "Slot index (0-based)"],
    name: Annotated[str, "New name for the function at that slot"],
) -> NameSlotResult:
    """Rename the function pointed to by vtable slot <index> (e.g. naming
    CBaseEntity vtable slot 39). Uses SN_FORCE so a name collision is suffixed
    rather than failing."""
    ea = _resolve_vtable_ea(vtable)
    if ea is None:
        raise IDAError(
            f"Could not resolve a vtable for {vtable!r}. Use list_rtti / find_vtables to locate one."
        )
    if index < 0:
        raise IDAError(f"Slot index must be >= 0 (got {index})")

    ps = _ptr_size()
    slot_ea = ea + index * ps
    if _slot_boundary(index, slot_ea):
        raise IDAError(
            f"Slot {index} is past the end of the vtable at {hex(ea)} "
            f"(another symbol begins at {hex(slot_ea)})."
        )
    func_ea = _read_ptr(slot_ea)
    if not _is_exec(func_ea):
        raise IDAError(
            f"Slot {index} does not point to code ({hex(func_ea)}); not a valid vtable slot."
        )

    old = ida_funcs.get_func_name(func_ea) or ida_name.get_name(func_ea) or ""
    ok = bool(idaapi.set_name(func_ea, name, ida_name.SN_NOWARN | ida_name.SN_FORCE))
    return {
        "vtable_ea": hex(ea),
        "index": index,
        "slot_ea": hex(slot_ea),
        "func_ea": hex(func_ea),
        "old_name": old,
        "new_name": (ida_name.get_name(func_ea) or name) if ok else old,
        "success": ok,
    }
