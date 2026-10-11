"""Evidence: the one record type, content-hash ids, the ledger and paging.

Every verb returns one Evidence. Its id hashes the canonical JSON of the
whole record, so recording the same record twice is a no-op and a tampered
JSONL line is rejected on load. A reply carries at most PAGE_BYTES of
canonical result: ``page`` cuts lists by item and strings by code point, and
``evidence(id, offset)`` returns the later pages.
"""

from __future__ import annotations

import json
import os
import sys
from collections import namedtuple
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from cleanroom.target import Fail

CONFIDENCE = ("observed", "derived", "inferred")
PAGE_BYTES = 65536
MAX_FILE = 256 << 20  # a ledger or import file is read whole; past this it is refused
LEDGER_HINT = "pass --ledger PATH or set CLEANROOM_LEDGER"
# A kind function returns this instead of a plain value when it inferred or missed something.
Finding = namedtuple("Finding", "value confidence unknowns")


def canonical(obj: Any) -> bytes:
    """JSON with sorted keys, no spaces, raw UTF-8 and no NaN, as bytes."""
    try:
        text = json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
        return text.encode("utf-8")
    except (TypeError, ValueError) as e:
        raise Fail("bad_input", f"not canonical JSON: {e}") from e


@dataclass(frozen=True)
class Evidence:
    """One finding: what was asked, of what, by which engine, and what came back."""

    op: str
    params: dict
    subject: dict | None
    engine: str
    result: Any
    confidence: str
    unknowns: tuple[str, ...] = ()
    locations: tuple[str, ...] = ()
    links: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.confidence not in CONFIDENCE:
            raise Fail("bad_input", f"confidence {self.confidence!r} is not one of {CONFIDENCE}")
        for name in ("unknowns", "locations", "links"):
            object.__setattr__(self, name, tuple(getattr(self, name)))

    @property
    def id(self) -> str:
        return "ev_" + sha256(canonical(asdict(self))).hexdigest()


def _line(ev: Evidence) -> str:
    return canonical({"id": ev.id, **asdict(ev)}).decode("utf-8")


def _read_jsonl(path: str, strict: bool = True) -> list[Evidence]:
    """Parse every line and recompute its id; one bad line rejects the whole file.

    A session ledger (``strict=False``) repairs its own tail instead: a last line
    with no newline that is not a record (a torn append) is cut off and reported on
    stderr, and a whole last line that lacks its newline gets one.
    """
    if not os.path.isfile(path):
        raise Fail("not_found", f"{path} is not a file")
    if os.path.getsize(path) > MAX_FILE:
        raise Fail("too_big", f"{path} is over {MAX_FILE} bytes", LEDGER_HINT)
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        raise Fail("not_found", f"cannot read {path}: {e}") from e
    lines, out = data.splitlines(keepends=True), []
    for n, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        torn = not strict and n == len(lines) and not raw.endswith(b"\n")
        try:
            rec = json.loads(raw)
            eid = rec.pop("id")
            ev = Evidence(**rec)
            if ev.id != eid:
                raise ValueError(f"id {eid} does not match its record")
        except (Fail, ValueError, TypeError, KeyError, AttributeError) as e:
            if not torn:
                raise Fail("bad_input", f"{path}:{n}: not an evidence record: {e}") from e
            os.truncate(path, len(data) - len(raw))
            print(f"cleanroom: {path}:{n}: dropped a torn last line", file=sys.stderr)
            break
        out.append(ev)
        if torn:
            with open(path, "ab") as f:
                f.write(b"\n")
    return out


class Ledger:
    """Evidence by id. With a path it is an append-only JSONL file, loaded on init."""

    def __init__(self, path: str | None = None):
        self.path = path
        self._records: dict[str, Evidence] = {}
        if path and os.path.exists(path):
            for ev in _read_jsonl(path, strict=False):
                self._records[ev.id] = ev

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self):
        return iter(self._records.values())

    def record(self, ev: Evidence) -> str:
        """Store ``ev`` and return its id. The same record twice is a no-op."""
        eid = ev.id
        old = self._records.get(eid)
        if old is not None:
            if old != ev and canonical(asdict(old)) != canonical(asdict(ev)):
                raise Fail("failed", f"{eid} is already recorded with different content")
            return eid
        if self.path:
            try:
                Path(self.path).parent.mkdir(parents=True, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(_line(ev) + "\n")
            except OSError as e:
                raise Fail("failed", f"cannot write ledger {self.path}: {e}", LEDGER_HINT) from e
        self._records[eid] = ev
        return eid

    def get(self, eid: str) -> Evidence:
        try:
            return self._records[eid]
        except KeyError:
            raise Fail("not_found", f"no evidence {eid}") from None

    def export(self, path: str, overwrite: bool = False) -> int:
        """Write every record as one JSONL line; refuse an existing file unless overwrite."""
        if os.path.exists(path) and not overwrite:
            hint = "export to another path, or remove the file first"
            raise Fail("bad_input", f"{path} exists", hint)
        tmp = f"{path}.{os.getpid()}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                for ev in self._records.values():
                    f.write(_line(ev) + "\n")
            os.replace(tmp, path)
        except OSError as e:
            raise Fail("failed", f"cannot write {path}: {e}") from e
        return len(self._records)

    def import_(self, path: str) -> int:
        """Merge a JSONL file after re-hashing every line; return how many were new."""
        records = _read_jsonl(path)  # every line is verified before any is merged
        before = len(self._records)
        for ev in records:
            self.record(ev)
        return len(self._records) - before


def _cut_items(items: list, offset: int, limit: int | None) -> list:
    """Items from ``offset`` whose canonical forms fit PAGE_BYTES together, at least one."""
    out: list = []
    used = 2  # the brackets
    stop = len(items) if limit is None else min(len(items), offset + limit)
    for i in range(offset, stop):
        item = items[i]
        n = len(canonical(item))
        if n > PAGE_BYTES:
            item = {"_too_big": i, "bytes": n}
            n = len(canonical(item))
        if out and used + n + 1 > PAGE_BYTES:
            break
        used += n + (1 if out else 0)
        out.append(item)
    return out


def _cut_text(text: str, offset: int, limit: int | None) -> str:
    """Code points from ``offset`` whose canonical form fits PAGE_BYTES, at least one."""
    tail = text[offset:] if limit is None else text[offset : offset + limit]
    tail = tail[:PAGE_BYTES]  # a code point is at least one byte, so the cut lies inside
    lo, hi = min(1, len(tail)), len(tail)
    while lo < hi:  # the largest prefix whose JSON form fits; never splits a code point
        mid = (lo + hi + 1) // 2
        if len(canonical(tail[:mid])) <= PAGE_BYTES:
            lo = mid
        else:
            hi = mid - 1
    return tail[:lo]


def _reply(ev: Evidence, result: Any) -> dict:
    return {
        "evidence_id": ev.id,
        "op": ev.op,
        "engine": ev.engine,
        "confidence": ev.confidence,
        "unknowns": list(ev.unknowns),
        "locations": list(ev.locations),
        "links": list(ev.links),
        "result": result,
    }


def page(ev: Evidence, offset: int = 0, limit: int | None = None) -> dict:
    """The reply for ``ev``: lists page by item, strings by code point, the rest as text.

    A value that fits PAGE_BYTES comes back whole and without a "page" key.
    Otherwise "page" gives the unit, this offset, the next one (None at the
    end) and the total. A list item that alone exceeds PAGE_BYTES becomes
    ``{"_too_big": index, "bytes": n}``; a dict or other value over the budget
    is rendered with ``json.dumps(indent=1)`` and paged as chars.
    """
    if offset < 0 or (limit is not None and limit < 1):
        raise Fail("bad_input", "offset must be 0 or more and limit 1 or more")
    result = ev.result
    whole = offset == 0 and limit is None
    if isinstance(result, list | tuple):
        result = list(result)
        unit, total = "items", len(result)
        part: Any = _cut_items(result, offset, limit)
    else:
        if not isinstance(result, str):
            if whole and len(canonical(result)) <= PAGE_BYTES:
                return _reply(ev, result)
            result = json.dumps(result, indent=1, sort_keys=True, ensure_ascii=False)
        unit, total = "chars", len(result)
        part = _cut_text(result, offset, limit)
    end = offset + len(part)
    nxt = end if end < total else None
    reply = _reply(ev, part)
    if offset or nxt is not None or part != result:
        reply["page"] = {"unit": unit, "offset": offset, "next": nxt, "total": total}
    return reply
