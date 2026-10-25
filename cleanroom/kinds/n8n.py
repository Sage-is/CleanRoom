"""n8n node packages: the node and credential descriptions ``n8n-nodes-base`` ships as JSON.

A target is the package, its ``dist/types``, or ``nodes.json`` beside ``credentials.json``.
Refs: ``npm@1`` (a node at a listed version label; bare ``npm`` is the newest),
``credential:npmApi`` and ``npm/package/get`` (an operation of its newest description).
The JSON keeps a function hook as ``null`` and drops a function ``authenticate``."""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cleanroom.evidence import Finding
from cleanroom.kinds.native import _match
from cleanroom.target import Fail, Target

LIST_WHAT = ("nodes", "credentials", "operations")
SHOW_VIEWS = ("auto", "info", "routing", "json")
DIFF_KEYS = dict.fromkeys(LIST_WHAT, "ref")
PARAM = re.compile(r"\$parameter(?:\.|\[[\"'])(\w+)")
HOOK = re.compile(r'"(?:preSend|postReceive)": \[[^\]]*null')
REQUEST_KEYS = ("routing", "requestDefaults", "authenticate", "test")
_list = builtins.list


def _files(path: str) -> tuple[str, str] | None:
    if os.path.isdir(path):
        tries = [os.path.join(path, *sub, "nodes.json") for sub in (("dist", "types"), ())]
        path = next((p for p in tries if os.path.isfile(p)), "")
    pair = path, os.path.join(os.path.dirname(path), "credentials.json")
    ok = os.path.basename(path) == "nodes.json" and all(map(os.path.isfile, pair))
    return pair if ok else None


def detect(path: str, head: bytes) -> bool:
    files = _files(path)
    with builtins.open(files[0] if files else os.devnull, "rb") as f:
        start = f.read(1 << 16).lstrip()
    return start[:1] == b"[" and b'"displayName"' in start and b'"name"' in start


@dataclass
class Handle:
    version: str
    nodes: dict[tuple[str, str], dict]  # (name, version label) -> description
    creds: dict[str, dict]
    content: str
    cache: dict[str, Any] = field(default_factory=dict)


def _label(d: dict) -> str:
    v = d.get("version", 1)
    return ",".join(str(x) for x in (v if isinstance(v, _list) else [v]))


def _rank(label: str) -> float:
    return max(float(x) for x in label.split(","))


def open(target: Target, engine: str | None = None, arch: str | None = None) -> Handle:
    """Read both files whole; the digest covers their bytes, not only names and sizes."""
    if engine not in (None, "builtin"):
        raise Fail("unsupported", f"n8n targets have one engine, builtin, not {engine!r}")
    files = _files(target.path)
    if files is None:
        raise Fail("bad_input", f"{target.path} has no nodes.json beside credentials.json")
    raw = [Path(p).read_bytes() for p in files]
    nodes, creds = (json.loads(r) for r in raw)
    meta = Path(files[0]).parent.parent.parent / "package.json"  # dist/types in a package
    pkg = json.loads(meta.read_text("utf-8")) if meta.is_file() else {}
    version = pkg.get("version", "unknown") if pkg.get("name") == "n8n-nodes-base" else "unknown"
    by_name = {(d["name"], _label(d)): d for d in nodes}
    digest = hashlib.sha256(b"\0".join(raw)).hexdigest()
    return Handle(version, by_name, {c["name"]: c for c in creds}, digest)


def close(handle: Handle) -> None: ...


def info(handle: Handle) -> dict:
    rows = _index(handle)["nodes"]
    return {
        "engine": "builtin-n8n", "format": f"n8n-nodes-base {handle.version}", "arch": "n8n-json",
        "nodes": len({r["name"] for r in rows}), "descriptions": len(rows),
        "declarative": sum(r["style"] == "declarative" for r in rows),
        "credentials": len(handle.creds), "content_sha256": handle.content, "views": [*SHOW_VIEWS],
    }  # fmt: skip


def _auth(c: dict) -> str:
    a = {"type": "oauth2"} if "oAuth2Api" in (c.get("extends") or []) else c.get("authenticate")
    return a.get("type", "object") if isinstance(a, dict) else "absent"


def _node(name: str, label: str, d: dict, rows: dict[str, _list[dict]]) -> None:
    text, ref = json.dumps(d.get("properties", [])), f"{name}@{label}"
    creds, routed = [c.get("name") for c in d.get("credentials", [])], '"routing"' in text
    rows["nodes"].append({
        "name": name, "ref": ref, "display": d.get("displayName"), "credentials": creds,
        "style": "declarative" if routed and "requestDefaults" in d else "programmatic",
        "base_url": (d.get("requestDefaults") or {}).get("baseURL", ""),
        "hooks": len(HOOK.findall(text)), "_raw": d,
    })  # fmt: skip
    rows["edges"] += [{"from": ref, "to": f"credential:{c}", "type": "credential"} for c in creds]


def _operations(name: str, label: str, d: dict, rows: dict[str, _list[dict]]) -> None:
    for p in (p for p in d.get("properties", []) if p.get("name") == "operation"):
        shown = ((p.get("displayOptions") or {}).get("show") or {}).get("resource") or [""]
        for res, o in ((r, o) for r in shown for o in p.get("options", [])):
            op = "/".join(str(x) for x in (name, res, o.get("value")) if x != "")
            text = json.dumps(o.get("routing") or {})
            req = (o.get("routing") or {}).get("request") or {}
            rows["operations"].append({
                "name": op, "ref": op, "node": f"{name}@{label}", "method": req.get("method", ""),
                "url": req.get("url", ""), "hooks": len(HOOK.findall(text)),
                "parameters": sorted(set(PARAM.findall(text))), "_raw": o,
            })  # fmt: skip
            rows["edges"].append({"from": f"{name}@{label}", "to": op, "type": "operation"})


def _index(h: Handle) -> dict[str, _list[dict]]:
    if "rows" not in h.cache:
        rows: dict[str, _list[dict]] = {w: [] for w in (*LIST_WHAT, "edges")}
        newest: dict[str, str] = {}
        for (name, label), d in h.nodes.items():
            _node(name, label, d, rows)
            if name not in newest or _rank(label) > _rank(newest[name]):
                newest[name] = label
        for name, label in sorted(newest.items()):
            _operations(name, label, h.nodes[(name, label)], rows)
        rows["credentials"] = [{
            "name": c["name"], "ref": f"credential:{c['name']}", "auth": _auth(c), "_raw": c,
            "fields": [p.get("name") for p in c.get("properties", [])], "test": "test" in c,
        } for c in h.creds.values()]  # fmt: skip
        h.cache["rows"] = rows
    return h.cache["rows"]


def _public(row: dict) -> dict:
    return {k: v for k, v in row.items() if not k.startswith("_")}


def list(handle: Handle, what: str, match: str | None = None) -> _list[dict] | Finding:
    """Inventory of ``what`` (see LIST_WHAT), optionally filtered by ``match``."""
    if what not in LIST_WHAT:
        raise Fail("bad_input", f"unknown what {what!r}", "one of " + ", ".join(LIST_WHAT))
    return _match([_public(r) for r in _index(handle)[what]], match)


def _resolve(h: Handle, ref: str) -> dict:
    """The row whose ref matches; a bare node name is its newest description."""
    rows, ref = _index(h), ref.strip()
    named = [r for r in rows["nodes"] if r["name"] == ref]
    hit = next((r for w in LIST_WHAT for r in rows[w] if r["ref"] == ref), None)
    hit = hit or max(named, key=lambda r: _rank(r["ref"].split("@")[1]), default=None)
    if hit is None:
        raise Fail("not_found", f"no {ref!r} in this package", "try list nodes --match")
    return hit


def show(handle: Handle, ref: str, view: str = "auto") -> dict:
    """A row (``info``), plus its links (``auto``), its request parts, or the raw JSON."""
    if view not in SHOW_VIEWS:
        raise Fail("bad_input", f"unknown view {view!r}", "one of " + ", ".join(SHOW_VIEWS))
    row = _resolve(handle, ref)
    if view in ("json", "routing"):
        raw = row["_raw"]
        return raw if view == "json" else {k: raw[k] for k in REQUEST_KEYS if k in raw}
    links = [e["to"] for e in _index(handle)["edges"] if e["from"] == row["ref"]]
    return {**_public(row), **({"links": links} if view == "auto" else {})}


def xrefs(handle: Handle, ref: str, direction: str = "both") -> _list[dict]:
    """Edges from or to a ref: node to credential and node to operation."""
    if direction not in ("to", "from", "both"):
        raise Fail("bad_input", f"unknown direction {direction!r}", "to, from or both")
    key, far = _resolve(handle, ref)["ref"], {"from": "to", "to": "from"}
    sides = ("from", "to") if direction == "both" else (direction,)
    return [
        {"ref": e[far[s]], "type": e["type"], **({"direction": s} if len(sides) > 1 else {})}
        for e in _index(handle)["edges"] for s in sides if e[s] == key
    ]  # fmt: skip
