"""The tool registry: one ``@tool`` makes the MCP tool, the CLI subcommand and the catalog entry.

A verb is ``fn(session, **params)``. Its type hints give the JSON schema and the argparse
flags, its docstring gives the descriptions, and ``invoke`` runs it: coerce the arguments,
take the session lock, call the function, wrap the value in Evidence, record it and page
it. The P0 verbs live at the bottom; ``graph.py`` adds ``trace`` and ``diff``.
"""

from __future__ import annotations

import importlib.metadata
import inspect
import keyword
import re
import sys
import threading
import types
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Union, get_args, get_origin, get_type_hints

from cleanroom import __version__
from cleanroom.evidence import Evidence, Finding, Ledger, page
from cleanroom.target import (
    Fail,
    Target,
    _kind_module,
    cache_dir,
    installed_kinds,
    open_target,
    unavailable,
)

SKILL_PATH = Path(__file__).parent / "skill" / "SKILL.md"
PAGING = ("offset", "limit")  # never part of Evidence.params
LIST_LIMIT = 200  # items per page for list and for evidence(id) on a list result
LOCK_WAIT = 120.0  # seconds a call waits for the session before failing timeout
_JSON = {str: "string", int: "integer", bool: "boolean", dict: "object"}
_HELP = re.compile(r"^\s*(\w+): (.+)$", re.M)
ENGINE_HINTS = {
    "ghidra": "install Ghidra 12 with JDK 21, set GHIDRA_INSTALL_DIR, then uv pip install"
    " 'cleanroom-re[ghidra]'",
    "ida": "only used when named: set IDADIR to an IDA Pro 9 install that ships idalib",
    "hopper": "install Hopper Disassembler under /Applications (macOS) or on PATH",
    "lldb": "xcode-select --install (macOS) or install lldb from your distribution",
    "jadx": "brew install jadx, or put the jadx launcher on PATH",
    "unblob": "pip install unblob, or brew install binwalk",
    "playwright": "uv pip install 'cleanroom-re[web]' && playwright install chromium",
}


@dataclass(frozen=True)
class Param:
    """One verb argument: its public name, raw hint, default and the Literal choices if any."""

    name: str
    hint: Any
    default: Any
    required: bool
    help: str
    choices: tuple | None


@dataclass(frozen=True)
class Spec:
    """A registered verb. ``params`` keeps declaration order; ``doc`` is the first paragraph."""

    name: str
    fn: Any
    doc: str
    params: dict[str, Param]
    read_only: bool
    needs_target: bool
    records: bool


REGISTRY: dict[str, Spec] = {}


def unwrap(hint: Any) -> tuple[Any, bool]:
    """``(base, optional)``: ``X | None`` is optional ``X``; any other union is refused."""
    if get_origin(hint) in (types.UnionType, Union):
        args = get_args(hint)
        rest = [a for a in args if a is not type(None)]
        if len(args) == 2 and len(rest) == 1:
            return rest[0], True
        raise TypeError(f"unsupported union hint {hint!r}")
    return hint, False


def json_type(hint: Any) -> dict:
    """The JSON schema fragment for a hint; raises TypeError for a hint the registry rejects."""
    base, optional = unwrap(hint)
    if get_origin(base) is Literal:
        out: dict = {"type": "string", "enum": list(get_args(base))}
    elif get_origin(base) is list and get_args(base) == (str,):
        out = {"type": "array", "items": {"type": "string"}}
    elif base in _JSON:
        out = {"type": _JSON[base]}
    else:
        raise TypeError(f"unsupported hint {hint!r}")
    if optional:
        out["type"] = [out["type"], "null"]
    return out


def _spec(fn, name: str | None, read_only: bool, needs_target: bool, records: bool) -> Spec:
    """Build a Spec from ``fn``'s signature (after the session) and its docstring."""
    hints = get_type_hints(fn)
    head, _, rest = (inspect.getdoc(fn) or "").partition("\n\n")
    helps = dict(_HELP.findall(rest))
    params: dict[str, Param] = {}
    for p in list(inspect.signature(fn).parameters.values())[1:]:
        if p.name not in hints:
            raise TypeError(f"{fn.__name__}.{p.name} has no type hint")
        hint = hints[p.name]
        json_type(hint)  # an unsupported hint fails here, at import
        base, _ = unwrap(hint)
        public = p.name.rstrip("_")
        required = p.default is inspect.Parameter.empty
        choices = get_args(base) if get_origin(base) is Literal else None
        default = None if required else p.default
        params[public] = Param(public, hint, default, required, helps.get(public, ""), choices)
    doc = " ".join(head.split())
    return Spec(
        (name or fn.__name__).rstrip("_"), fn, doc, params, read_only, needs_target, records
    )


def tool(fn=None, *, name=None, read_only=True, needs_target=True, records=True):
    """Register a verb. Bare ``@tool`` or ``@tool(needs_target=False)`` both work.

    ``needs_target`` makes the CLI open ``-t`` first and MCP fail not_found without an
    open target. ``records=False`` means the function returns the reply itself instead
    of a value to wrap in Evidence.
    """

    def wrap(f):
        spec = _spec(f, name, read_only, needs_target, records)
        REGISTRY[spec.name] = spec
        return f

    return wrap(fn) if fn is not None else wrap


def _check(p: Param, value: Any) -> Any:
    """``value`` for ``p``, or Fail bad_input. A bool is never an int."""
    base, optional = unwrap(p.hint)
    if value is None:
        if optional:
            return None
        raise Fail("bad_input", f"{p.name} must not be null")
    if p.choices is not None:
        if value not in p.choices:
            raise Fail(
                "bad_input", f"{p.name} must be one of {', '.join(p.choices)}, not {value!r}"
            )
        return value
    kind = get_origin(base) or base
    if kind is list:
        ok = isinstance(value, list) and all(isinstance(x, str) for x in value)
    else:
        ok = isinstance(value, kind) and not (kind is int and isinstance(value, bool))
    if not ok:
        want = json_type(p.hint)["type"]
        raise Fail("bad_input", f"{p.name} must be {want}, not {type(value).__name__}")
    return value


def coerce(spec: Spec, args: dict) -> dict:
    """Validate ``args`` against ``spec`` and fill defaults: the only validator."""
    if not isinstance(args, dict):
        raise Fail("bad_input", f"{spec.name} arguments must be an object")
    unknown = sorted(set(args) - set(spec.params))
    if unknown:
        known = ", ".join(spec.params) or "none"
        raise Fail("bad_input", f"{spec.name} has no parameter {', '.join(unknown)}", known)
    out = {}
    for name, p in spec.params.items():
        if name in args:
            out[name] = _check(p, args[name])
        elif p.required:
            raise Fail("bad_input", f"{spec.name} needs {name}", p.help or None)
        else:
            out[name] = p.default
    return out


def schema(spec: Spec) -> dict:
    """The JSON schema of ``spec``'s arguments, as the catalog and MCP publish it."""
    props = {}
    for name, p in spec.params.items():
        prop = json_type(p.hint)
        if p.help:
            prop["description"] = p.help
        if p.default is not None:
            prop["default"] = p.default
        props[name] = prop
    required = [n for n, p in spec.params.items() if p.required]
    return {
        "type": "object",
        "properties": props,
        "required": required,
        "additionalProperties": False,
    }


class Session:
    """One open target with its kind module and handle, the ledger, and a lock round each verb."""

    def __init__(self, ledger: Ledger):
        self.ledger = ledger
        self.target: Target | None = None
        self.kind: Any = None
        self.handle: Any = None
        self.lock = threading.Lock()

    def bind(self, target: Target, kind_module: Any, handle: Any) -> None:
        self.target, self.kind, self.handle = target, kind_module, handle

    def require(self) -> tuple[Target, Any, Any]:
        if self.target is None:
            raise Fail("not_found", "no target open", "call open first")
        return self.target, self.kind, self.handle

    def close(self) -> None:
        """Close the kind handle (its workers go with it); the ledger stays."""
        kind, handle = self.kind, self.handle
        self.target = self.kind = self.handle = None
        if kind is not None and hasattr(kind, "close"):
            kind.close(handle)


def kind_call(kind: Any, name: str, *args: Any, **kw: Any) -> Any:
    """Call ``kind.<name>``; a kind without that function makes the verb unsupported."""
    fn = getattr(kind, name, None)
    if fn is None:
        short = kind.__name__.rsplit(".", 1)[-1]
        raise Fail("unsupported", f"{short} targets do not support {name}")
    return fn(*args, **kw)


def plain(value: Any) -> Any:
    """A kind's value without its Finding wrapper."""
    return value.value if isinstance(value, Finding) else value


def _subject(session: Session) -> tuple[dict | None, str]:
    """The Evidence subject and engine string for the open target, or (None, "cleanroom")."""
    t = session.target
    if t is None:
        return None, "cleanroom"
    info = plain(kind_call(session.kind, "info", session.handle))
    subject = {"path": t.path, "sha256": t.sha256, "kind": t.kind}
    subject.update({k: info.get(k) for k in ("format", "arch")})
    return subject, str(info.get("engine") or "unknown")


def _kwargs(args: dict) -> dict:
    """Python keyword names for public ones: ``import`` becomes ``import_``."""
    return {k + "_" if keyword.iskeyword(k) else k: v for k, v in args.items()}


def invoke(session: Session, spec: Spec, args: dict) -> dict:
    """Run a verb: coerce, lock, call, wrap in Evidence, record, page.

    A ``records=False`` verb returns its own reply dict. A kind value may be a
    ``Finding``; its confidence and unknowns go into the record. ``offset`` and
    ``limit`` select the page and never reach ``Evidence.params``.
    """
    kw = coerce(spec, args)
    if not session.lock.acquire(timeout=LOCK_WAIT):
        raise Fail("timeout", "another call is still running", f"retry after {LOCK_WAIT:g} s")
    try:
        if spec.needs_target:
            session.require()
        before = _subject(session) if spec.records else None
        value = spec.fn(session, **_kwargs(kw))
        if not spec.records:
            return value
        after = _subject(session)  # the target now bound; before only when the verb closed it
        subject, engine = after if after[0] is not None else before
        confidence, unknowns = "observed", ()
        if isinstance(value, Finding):
            value, confidence, unknowns = value
        if isinstance(value, Iterator):
            value = list(value)
        params = {k: v for k, v in kw.items() if k not in PAGING}
        ev = Evidence(spec.name, params, subject, engine, value, confidence, tuple(unknowns))
        session.ledger.record(ev)
        return page(ev, kw.get("offset", 0), kw.get("limit"))
    finally:
        session.lock.release()


@tool(needs_target=False)
def open_(
    session: Session,
    path: str,
    kind: str | None = None,
    engine: str | None = None,
    arch: str | None = None,
) -> dict:
    """Detect and bind a target; replies with its identity, engine, format and vocabulary.

    path: a file, a directory (app bundle, JS tree) or an http(s) URL
    kind: override detection; needed for evm bytecode
    engine: native engine: ghidra, hopper, builtin, or ida when installed
    arch: the FAT slice to open, such as arm64 or x86_64; default is the host
    """
    session.close()
    target = open_target(path, kind)
    module = _kind_module(target.kind)
    if module is None:  # a URL is always web, which lands in P2
        raise unavailable(target.kind)
    handle = kind_call(module, "open", target, engine=engine, arch=arch)
    session.bind(target, module, handle)
    info = plain(kind_call(module, "info", handle))
    head = {"path": target.path, "sha256": target.sha256, "size": target.size, "kind": target.kind}
    views = list(info.get("views") or module.SHOW_VIEWS)  # info narrows them per engine
    return {**head, **info, "list": list(getattr(module, "LIST_WHAT", ())), "views": views}


@tool
def close(session: Session) -> dict:
    """Close the open target and its workers; the session's Evidence stays."""
    target, _, _ = session.require()
    session.close()
    return {"closed": target.path}


@tool
def list_(
    session: Session,
    what: str,
    match: str | None = None,
    offset: int = 0,
    limit: int = LIST_LIMIT,
) -> list:
    """List items of one class: functions, strings, sections, files, requests and so on.

    what: an item class the open kind lists (open replies with the vocabulary)
    match: keep only items whose name or text contains this (kinds may accept a regex)
    offset: first item of the page
    limit: items per page (1 or more); evidence(id) pages the same record the same way
    """
    target, kind, handle = session.require()
    if what not in kind.LIST_WHAT:
        raise Fail("bad_input", f"{target.kind} lists {', '.join(kind.LIST_WHAT)}, not {what!r}")
    return kind_call(kind, "list", handle, what, match)


@tool
def show(session: Session, ref: str, view: str = "auto") -> dict | str:
    """Inspect one item: a function, string, file, request or class, in the view asked for.

    ref: a name, an address such as 0x100003f20 or space:0x10, or a path
    view: auto picks the most useful view; others are kind specific (pseudo, asm, info, ...)
    """
    target, kind, handle = session.require()
    if view not in kind.SHOW_VIEWS:
        raise Fail(
            "bad_input", f"{target.kind} views are {', '.join(kind.SHOW_VIEWS)}, not {view!r}"
        )
    return kind_call(kind, "show", handle, ref, view)


@tool
def xrefs(session: Session, ref: str, direction: Literal["to", "from", "both"] = "both") -> list:
    """References into, out of, or both ways from an item: calls, jumps, data, strings, imports.

    ref: the item, as for show
    direction: to (who uses it), from (what it uses) or both
    """
    _, kind, handle = session.require()
    return kind_call(kind, "xrefs", handle, ref, direction)


def _row(ev: Evidence) -> dict:
    """One ledger listing entry: enough to tell two list records of different files apart."""
    sub = ev.subject or {}
    head = {"id": ev.id, "op": ev.op, "params": ev.params}
    return {**head, "path": sub.get("path"), "sha256": sub.get("sha256"), "engine": ev.engine}


@tool(needs_target=False, records=False, read_only=False)
def evidence(
    session: Session,
    id: str | None = None,
    offset: int = 0,
    limit: int | None = None,
    export: str | None = None,
    import_: str | None = None,
) -> dict:
    """Page a stored record, list the ledger, or export and import JSONL records.

    id: an ev_ id; its reply is re-paged from offset
    offset: first item or character of the page, of the record or of the listing
    limit: items or characters per page; a list defaults to 200 as list does, text fills 64 KiB
    export: write every record to this JSONL file (refuses to overwrite; not with import)
    import: merge records from this JSONL file; ids are recomputed and must match
    """
    led = session.ledger
    if export and import_:
        raise Fail("bad_input", "export and import are exclusive", "make two calls")
    if export:
        return {"exported": led.export(export), "path": export}
    if import_:
        return {"imported": led.import_(import_), "path": import_}
    if id is None:
        index = Evidence("evidence", {}, None, "cleanroom", [_row(ev) for ev in led], "observed")
        paged = page(index, offset, limit)
        rows = {"count": len(led), "ledger": led.path, "records": paged["result"]}
        return {**rows, **({"page": paged["page"]} if "page" in paged else {})}
    ev = led.get(id)
    if limit is None and isinstance(ev.result, list | tuple):
        limit = LIST_LIMIT
    return page(ev, offset, limit)


def _version(dist: str) -> str | None:
    try:
        return importlib.metadata.version(dist)
    except importlib.metadata.PackageNotFoundError:
        return None


@tool(needs_target=False, records=False)
def doctor(session: Session) -> dict:
    """Report engines, libraries, verbs, the skill path and what to install for the rest."""
    from cleanroom.engines import probe_all

    engines = probe_all()
    hints = {k: v for k, v in ENGINE_HINTS.items() if not engines.get(k)}
    return {
        "version": __version__,
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "engines": engines,
        "hints": hints,
        "libraries": {d: _version(d) for d in ("mcp", "lief", "capstone", "psutil")},
        "kinds": installed_kinds(),
        "tools": sorted(REGISTRY),
        "skill": str(SKILL_PATH) if SKILL_PATH.is_file() else None,
        "ledger": session.ledger.path,
        "cache": str(cache_dir()),
    }
