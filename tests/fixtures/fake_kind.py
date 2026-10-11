"""A complete kind module over an in-memory toy, for the tools, CLI and MCP tests.

A fake target is any file whose head starts with ``b"FAKE"``. The tests register
this module as ``cleanroom.kinds.fake`` through ``sys.modules`` (in process) or
through the ``CLEANROOM_EXTRA_KINDS`` / ``CLEANROOM_TEST_KINDS_PATH`` hook in
``cleanroom.__main__`` (subprocesses). ``xrefs`` returns a Finding with
confidence "inferred" so the Evidence plumbing for findings is exercised.
"""

from __future__ import annotations

import builtins

from cleanroom.evidence import Finding
from cleanroom.target import Fail, Target, parse_ref

LIST_WHAT = ("things",)
SHOW_VIEWS = ("auto", "info")
DIFF_KEYS = {"things": "name"}
DIFF_IGNORE = {"at"}
THINGS = [
    {"name": "alpha", "ref": "0x10", "size": 3},
    {"name": "beta", "ref": "0x20", "size": 5},
    {"name": "gamma", "ref": "0x30", "size": 8},
]
MAGIC = b"FAKE"


def detect(path: str, head: bytes) -> bool:
    return head.startswith(MAGIC)


def open(target: Target, engine: str | None = None, arch: str | None = None) -> dict:
    return {"target": target, "engine": engine or "fake 1.0", "arch": arch or "toy", "open": True}


def info(handle: dict) -> dict:
    return {
        "engine": handle["engine"],
        "format": "fake",
        "arch": handle["arch"],
        "things": len(THINGS),
    }


def _find(ref: str) -> dict:
    parsed = parse_ref(ref)
    for thing in THINGS:
        if parsed[0] == "addr" and int(thing["ref"], 16) == parsed[1]:
            return thing
        if parsed[0] == "name" and thing["name"] == parsed[1]:
            return thing
    raise Fail("not_found", f"no thing {ref!r}", "list things")


def list(handle: dict, what: str, match: str | None = None) -> builtins.list[dict]:
    items = [dict(t) for t in THINGS if not match or match.lower() in t["name"]]
    return items


def show(handle: dict, ref: str, view: str = "auto") -> dict:
    thing = _find(ref)
    if view == "info":
        return {"name": thing["name"], "ref": thing["ref"], "view": "info"}
    return {**thing, "view": view, "text": f"thing {thing['name']} at {thing['ref']}"}


def xrefs(handle: dict, ref: str, direction: str = "both") -> Finding:
    thing = _find(ref)
    items = []
    if direction in ("to", "both") and thing["name"] != "alpha":
        items.append({"ref": "0x10", "name": "alpha", "type": "call", "at": "0x14"})
    if direction in ("from", "both") and thing["name"] != "gamma":
        items.append({"ref": "0x30", "name": "gamma", "type": "data", "at": thing["ref"]})
    return Finding(items, "inferred", ("toy xref scan; no real control flow",))


def close(handle: dict) -> None:
    handle["open"] = False
