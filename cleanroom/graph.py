"""Graph verbs for every kind: ``trace`` walks xrefs breadth first, ``diff`` keys two inventories.

Neither reads a target itself. ``trace`` asks the open kind for ``xrefs(ref, "from")`` one
node at a time. ``diff`` compares ``list`` records (an ``ev_`` id, or a path opened in a
temporary session) keyed by the kind's ``DIFF_KEYS`` with ``DIFF_IGNORE`` fields dropped;
an incomplete side makes the category ``unknown``, never a claim (design 9, case 15).
"""

from __future__ import annotations

import importlib
import re
from collections import deque
from typing import Any

from cleanroom.evidence import Evidence, Finding, canonical, page
from cleanroom.target import Fail, parse_ref
from cleanroom.tools import REGISTRY, Session, invoke, kind_call, plain, tool

# Edge types the search walks through; data and string edges end at their target.
EXPAND = ("call", "jump", "import")
EV_ID = re.compile(r"ev_[0-9a-f]{64}")
# Per category, the show view whose text decides "changed" once the listed fields agree.
PROBE = {"functions": "asm"}
# Hex of four digits or more in that text is an address and is masked; immediates stay.
ADDRESS = re.compile(r"0x[0-9a-fA-F]{4,}")
_UNPROBED = "{cat}: only listed fields compared; pass paths to diff to compare {view} bodies"


def _key(ref: str) -> str:
    """One key for an address however it is spelled; any other ref is its own key."""
    try:
        parsed = parse_ref(ref)
    except Fail:
        return ref
    return f"0x{parsed[1]:x}" if parsed[0] == "addr" else ref


def _locate(kind: Any, handle: Any, ref: str) -> dict:
    """``{"ref", "name", "data"}`` as ``show`` reports it; a ref it cannot resolve is data."""
    try:
        info = plain(kind_call(kind, "show", handle, ref, "auto"))
    except Fail as e:
        if e.code not in ("not_found", "unsupported"):
            raise
        return {"ref": ref, "name": ref, "data": True}
    info = info if isinstance(info, dict) else {}
    where = info.get("address") or info.get("ref") or ref
    return {"ref": str(where), "name": str(info.get("name") or ref), "data": False}


def _same(goal: dict, node: dict) -> bool:
    """Names match modulo the Mach-O underscore (``puts`` reaches ``_puts``), or the refs do."""
    a, b = node["name"].removeprefix("_"), goal["name"].removeprefix("_")
    return a == b != "" or _key(node["ref"]) == _key(goal["ref"])


def _walk(kind: Any, handle: Any, root: dict, goal: dict | None, depth: int, cap: int) -> tuple:
    """Breadth first over ``xrefs(ref, "from")``; nodes keyed by address, first hit is shortest."""
    start = _key(root["ref"])
    nodes = {start: {"ref": root["ref"], "name": root["name"]}}
    parent: dict[str, str | None] = {start: None}
    edges: dict[tuple, dict] = {}
    unknowns: list[str] = []
    queue = deque([(root["ref"], 0)])
    found = start if goal and _same(goal, root) else None
    truncated = deeper = False
    while queue and found is None and not truncated:
        ref, d = queue.popleft()
        if d >= depth:
            deeper = True
            continue
        try:
            items = kind_call(kind, "xrefs", handle, ref, "from")
        except Fail as e:
            if e.code != "not_found" or d == 0:
                raise
            unknowns.append(f"no xrefs from {ref}: {e.message}")
            continue
        if isinstance(items, Finding):
            unknowns.extend(items.unknowns)
            items = items.value
        for item in items:
            typ, to = str(item.get("type") or ""), str(item.get("ref") or "")
            if typ not in EXPAND and not (goal and goal["data"]):
                continue
            k, new = _key(to), _key(to) not in nodes
            if new:
                if len(nodes) >= cap:
                    truncated = True
                    break
                nodes[k] = {"ref": to, "name": str(item.get("name") or "")}
                parent[k] = _key(ref)
                if typ in EXPAND:
                    queue.append((to, d + 1))
            edges.setdefault((_key(ref), k, typ), {"from": ref, "to": to, "type": typ})
            if new and goal and _same(goal, nodes[k]):
                found = k
                break
    path, k = [], found
    while k is not None:
        path.insert(0, nodes[k]["ref"])
        k = parent[k]
    if truncated:
        unknowns.append("truncated at max_nodes")
    elif goal and found is None and deeper:
        unknowns.append(f"depth {depth} reached before the goal; deeper paths not searched")
    head = {"start": root["ref"], "goal": goal and goal["ref"], "found": found is not None}
    graph = {"path": path, "nodes": list(nodes.values()), "edges": list(edges.values())}
    return {**head, **graph, "truncated": truncated}, unknowns


@tool
def trace(
    session: Session, start: str, goal: str | None = None, depth: int = 3, max_nodes: int = 500
) -> Finding:
    """Walk xrefs breadth first from one item, through calls and jumps, to a goal or a depth.

    start: the item to begin at, as for show
    goal: stop once this item is reached; a string or data ref also follows data edges
    depth: hops to follow from start
    max_nodes: stop after this many items and say so
    """
    _, kind, handle = session.require()
    if depth < 0 or max_nodes < 1:
        raise Fail("bad_input", "depth must be 0 or more and max_nodes 1 or more")
    root = _locate(kind, handle, start)
    target = _locate(kind, handle, goal) if goal is not None else None
    result, unknowns = _walk(kind, handle, root, target, depth, max_nodes)
    if target and target["data"]:
        unknowns.insert(0, f"{goal} is not a function here; data and string edges were followed")
    return Finding(result, "derived", tuple(dict.fromkeys(unknowns)))


def _record(session: Session, ref: str, what: str | None) -> dict:
    """An ``ev_`` side: the list record from the ledger, under its category."""
    ev = session.ledger.get(ref)
    cat = ev.params.get("what") if ev.op == "list" else None
    if cat is None:
        raise Fail("bad_input", f"{ref} is a {ev.op} record, not a list", "diff takes list ids")
    if what and cat != what:
        raise Fail("bad_input", f"{ref} lists {cat}, not {what}")
    if ev.params.get("match"):  # a filtered inventory cannot support added or removed
        raise Fail("bad_input", f"{ref} is a filtered list (match={ev.params['match']!r})")
    sub = ev.subject or {}
    return {**{k: sub.get(k) for k in ("kind", "path", "sha256")}, "lists": {cat: ev}}


def _keys(module: Any) -> dict[str, str]:
    keys = getattr(module, "DIFF_KEYS", None)
    if not keys:
        raise Fail("unsupported", f"{module.__name__.rsplit('.', 1)[-1]} has no diff keys")
    return keys


def _opened(session: Session, path: str, cats: list[str] | None) -> dict:
    """A path side: detect and open it in its own session on the shared ledger, list ``cats``."""
    tmp = Session(session.ledger)
    try:
        args = {"path": path, "kind": None, "engine": None, "arch": None}
        head = invoke(tmp, REGISTRY["open"], args)["result"]
        keys, lists = _keys(tmp.kind), {}
        for cat in [c for c in cats or keys if c in keys]:
            reply = invoke(tmp, REGISTRY["list"], {"what": cat})
            lists[cat] = session.ledger.get(reply["evidence_id"])
    except BaseException:
        tmp.close()
        raise
    return {**{k: head[k] for k in ("kind", "path", "sha256")}, "lists": lists, "session": tmp}


def _index(items: Any, key: str, ignore: set) -> tuple[dict, dict, int]:
    """Items by key with ignored fields dropped, a show ref per key, and the unkeyed count."""
    groups, refs, unkeyed = {}, {}, 0
    for item in items if isinstance(items, list) else []:
        k = item.get(key) if isinstance(item, dict) else None
        if k in (None, ""):
            unkeyed += 1
            continue
        groups.setdefault(str(k), []).append({f: v for f, v in item.items() if f not in ignore})
        refs.setdefault(str(k), str(item.get("address") or item.get("ref") or k))
    for group in groups.values():
        group.sort(key=canonical)
    return groups, refs, unkeyed


def _text(side: dict, ref: str, view: str, unknowns: list[str]) -> str | None:
    """``show(ref, view)`` through the side's open session, addresses masked; None on a Fail."""
    try:
        value = plain(kind_call(side["session"].kind, "show", side["session"].handle, ref, view))
    except Fail as e:
        unknowns.append(f"show {ref} {view} on {side['path']}: {e.message}")
        return None
    text = value if isinstance(value, str) else canonical(value).decode("utf-8")
    return ADDRESS.sub("0x_", text)


def _compare(sides: list, cat: str, key: str, ignore: set, view: str | None, gaps: list) -> dict:
    """One category: keys on one side, keys whose fields or view text differ, unkeyed counts.
    What it cannot see (bodies without a handle, unkeyed items) makes it unknown, not unchanged."""
    probe, same = all("session" in s for s in sides), sides[0]["sha256"] == sides[1]["sha256"]
    left, right = (s["lists"][cat] for s in sides)
    (la, ra, ua), (lb, rb, ub) = (_index(ev.result, key, ignore) for ev in (left, right))
    complete = True
    for name, ev in (("a", left), ("b", right)):
        if ev.unknowns or not isinstance(ev.result, list):
            complete = False
            why = "; ".join(ev.unknowns) or "the result is not a list"
            gaps.append(f"{cat}: {name} is incomplete: {why}")
    changed = []
    for k in sorted(la.keys() & lb.keys()):
        differs = la[k] != lb[k]
        if not differs and probe and view and len(la[k]) == 1 == len(lb[k]):
            texts = [_text(s, r[k], view, gaps) for s, r in zip(sides, (ra, rb), strict=True)]
            differs = None not in texts and texts[0] != texts[1]
        if differs:
            changed.append(k)
    report: dict = {}
    if complete:
        report = {"added": sorted(lb.keys() - la.keys()), "removed": sorted(la.keys() - lb.keys())}
    report["changed"] = changed
    report["unchanged"] = len(la.keys() & lb.keys()) - len(changed)
    if ua or ub:
        report["unkeyed"] = [ua, ub]
    moved = bool(changed or report.get("added") or report.get("removed") or ua != ub)
    blind = [] if same else [_UNPROBED.format(cat=cat, view=view)] if view and not probe else []
    if (ua or ub) and not moved and not same:
        blind.append(f"{cat}: {ua} and {ub} unkeyed items were not compared")
    gaps.extend(blind)
    unsure = not complete or (blind and not moved)
    report["status"] = "unknown" if unsure else "changed" if moved else "unchanged"
    return report


@tool(needs_target=False, records=False)
def diff(session: Session, a: str, b: str, what: str | None = None) -> dict:
    """Compare two inventories by stable keys: added, removed and changed, or unknown when cut.

    a: an ev_ id of a list record, or a path to open and list
    b: the other side, likewise
    what: one category to compare; default is every category the kind keys
    """
    sides = [_record(session, r, what) if EV_ID.fullmatch(r) else {"path": r} for r in (a, b)]
    cats = [what] if what else sorted({c for s in sides for c in s.get("lists", ())}) or None
    temps: list[Session] = []
    try:
        for i, s in enumerate(sides):
            if "lists" not in s:
                sides[i] = s = _opened(session, s["path"], cats)
                temps.append(s["session"])
                cats = list(s["lists"])
        kind = sides[0]["kind"]
        module = importlib.import_module(f"cleanroom.kinds.{kind}")
        keys, ignore = _keys(module), set(getattr(module, "DIFF_IGNORE", ()))
        if what and what not in keys:
            raise Fail("bad_input", f"{kind} diffs {', '.join(keys)}, not {what!r}")
        if any(s["kind"] != kind or any(c not in s["lists"] for c in cats) for s in sides):
            have = [f"{'ab'[i]} {s['kind']} {', '.join(s['lists'])}" for i, s in enumerate(sides)]
            raise Fail("bad_input", "the sides do not match: " + "; ".join(have))
        reports, unknowns = {}, []
        for cat in cats:
            view = PROBE.get(cat) if PROBE.get(cat) in module.SHOW_VIEWS else None
            reports[cat] = _compare(sides, cat, keys[cat], ignore, view, unknowns)
    finally:
        for tmp in temps:
            tmp.close()
    seen = {r["status"] for r in reports.values()}
    result = {
        "a": {"path": sides[0]["path"], "sha256": sides[0]["sha256"]},
        "b": {"path": sides[1]["path"], "sha256": sides[1]["sha256"]},
        "kind": kind,
        "status": next((s for s in ("unknown", "changed") if s in seen), "unchanged"),
        "categories": reports,
    }
    links = tuple(s["lists"][c].id for c in cats for s in sides)
    params = {"a": a, "b": b, "what": what}
    why = tuple(dict.fromkeys(unknowns))
    ev = Evidence("diff", params, None, "cleanroom", result, "derived", why, (), links)
    session.ledger.record(ev)
    return page(ev)
