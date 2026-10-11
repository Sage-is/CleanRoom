"""tools.py: the registry, coerce, schema, Session and invoke, over tests/fixtures/fake_kind."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Literal

import pytest

from cleanroom import target, tools
from cleanroom.evidence import Ledger
from cleanroom.target import Fail, open_target
from cleanroom.tools import REGISTRY, Session, coerce, invoke, schema
from tests.fixtures import fake_kind

P0_VERBS = ("open", "close", "list", "show", "xrefs", "evidence", "doctor")


@pytest.fixture(autouse=True)
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CLEANROOM_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("CLEANROOM_LEDGER", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setitem(sys.modules, "cleanroom.kinds.fake", fake_kind)
    monkeypatch.setattr(target, "KIND_ORDER", ("fake", *target.KIND_ORDER))


@pytest.fixture
def fake_file(tmp_path: Path) -> Path:
    p = tmp_path / "toy.bin"
    p.write_bytes(b"FAKE\x00toy")
    return p


@pytest.fixture
def session(tmp_path: Path) -> Session:
    return Session(Ledger(str(tmp_path / "ledger.jsonl")))


@pytest.fixture
def bound(session: Session, fake_file: Path) -> Session:
    """A session bound by hand, so the ledger holds no open record."""
    t = open_target(str(fake_file))
    session.bind(t, fake_kind, fake_kind.open(t))
    return session


def fail(fn, code: str, *args, **kw) -> Fail:
    with pytest.raises(Fail) as info:
        fn(*args, **kw)
    assert info.value.code == code, str(info.value)
    return info.value


# --- registry and schema ---------------------------------------------------------


def test_registry_holds_the_p0_verbs() -> None:
    assert set(P0_VERBS) <= set(REGISTRY)
    assert not any(n.endswith("_") for n in REGISTRY)
    assert REGISTRY["open"].needs_target is False and REGISTRY["open"].records is True
    for name in ("doctor", "evidence"):
        assert REGISTRY[name].needs_target is False and REGISTRY[name].records is False
    assert REGISTRY["list"].doc.startswith("List items")
    assert all(s.read_only for n, s in REGISTRY.items() if n != "evidence")
    assert REGISTRY["evidence"].read_only is False  # export writes, import mutates the ledger


def test_schema_list_snapshot() -> None:
    s = schema(REGISTRY["list"])
    assert s["required"] == ["what"]
    assert s["additionalProperties"] is False
    assert list(s["properties"]) == ["what", "match", "offset", "limit"]
    assert s["properties"]["what"]["type"] == "string"
    assert s["properties"]["match"]["type"] == ["string", "null"]
    assert s["properties"]["offset"] == {
        "type": "integer",
        "description": "first item of the page",
        "default": 0,
    }
    assert s["properties"]["limit"]["type"] == "integer"
    assert s["properties"]["limit"]["default"] == 200


def test_schema_open_snapshot() -> None:
    s = schema(REGISTRY["open"])
    assert list(s["properties"]) == ["path", "kind", "engine", "arch"]
    assert s["required"] == ["path"]
    assert s["properties"]["path"]["type"] == "string"
    for name in ("kind", "engine", "arch"):
        assert s["properties"][name]["type"] == ["string", "null"]
        assert "default" not in s["properties"][name]
    assert "http" in s["properties"]["path"]["description"]


def test_schema_literal_is_enum_and_import_loses_underscore() -> None:
    assert schema(REGISTRY["xrefs"])["properties"]["direction"] == {
        "type": "string",
        "enum": ["to", "from", "both"],
        "description": "to (who uses it), from (what it uses) or both",
        "default": "both",
    }
    assert "import" in schema(REGISTRY["evidence"])["properties"]
    assert "import_" not in REGISTRY["evidence"].params


def test_tool_rejects_unsupported_hints() -> None:
    def floaty(session: Session, x: float) -> dict:
        return {}

    def union(session: Session, x: int | str) -> dict:
        return {}

    def bare(session: Session, x) -> dict:
        return {}

    for fn in (floaty, union, bare):
        with pytest.raises(TypeError):
            tools.tool(fn, name="never")
    assert "never" not in REGISTRY


def test_tool_accepts_every_mapped_hint() -> None:
    def rich(
        session: Session,
        a: str,
        b: int = 1,
        c: bool = False,
        d: Literal["x", "y"] = "x",
        e: list[str] | None = None,
        f: dict | None = None,
    ) -> dict:
        return {}

    spec = tools._spec(rich, "rich", True, False, False)
    types = {n: schema(spec)["properties"][n]["type"] for n in spec.params}
    assert types == {
        "a": "string",
        "b": "integer",
        "c": "boolean",
        "d": "string",
        "e": ["array", "null"],
        "f": ["object", "null"],
    }
    assert coerce(spec, {"a": "s", "e": ["p"], "f": {"k": 1}})["e"] == ["p"]
    fail(coerce, "bad_input", spec, {"a": "s", "e": [1]})
    fail(coerce, "bad_input", spec, {"a": "s", "c": 1})


# --- coerce ----------------------------------------------------------------------


def test_coerce_rejects_unknown_keys() -> None:
    err = fail(coerce, "bad_input", REGISTRY["list"], {"what": "things", "nope": 1})
    assert "nope" in err.message


def test_coerce_rejects_bool_for_int() -> None:
    fail(coerce, "bad_input", REGISTRY["list"], {"what": "things", "limit": True})
    fail(coerce, "bad_input", REGISTRY["list"], {"what": "things", "offset": "3"})


def test_coerce_rejects_bad_enum_and_wrong_types() -> None:
    fail(coerce, "bad_input", REGISTRY["xrefs"], {"ref": "a", "direction": "sideways"})
    fail(coerce, "bad_input", REGISTRY["show"], {"ref": 12})
    fail(coerce, "bad_input", REGISTRY["list"], ["what"])


def test_coerce_fills_defaults_and_handles_null() -> None:
    assert coerce(REGISTRY["list"], {"what": "things"}) == {
        "what": "things",
        "match": None,
        "offset": 0,
        "limit": 200,
    }
    assert coerce(REGISTRY["list"], {"what": "things", "match": None})["match"] is None
    fail(coerce, "bad_input", REGISTRY["list"], {"what": "things", "offset": None})
    err = fail(coerce, "bad_input", REGISTRY["list"], {})
    assert "what" in err.message


# --- invoke ----------------------------------------------------------------------


def test_invoke_without_target_fails_not_found(session: Session) -> None:
    err = fail(invoke, "not_found", session, REGISTRY["list"], {"what": "things"})
    assert err.message == "no target open"
    assert len(session.ledger) == 0


def test_open_binds_and_records(session: Session, fake_file: Path) -> None:
    reply = invoke(session, REGISTRY["open"], {"path": str(fake_file)})
    assert reply["result"]["kind"] == "fake"
    assert reply["result"]["engine"] == "fake 1.0"
    assert reply["result"]["list"] == ["things"] and reply["result"]["views"] == ["auto", "info"]
    assert reply["engine"] == "fake 1.0" and reply["confidence"] == "observed"
    assert session.target is not None and session.target.kind == "fake"
    ev = session.ledger.get(reply["evidence_id"])
    assert ev.subject == {
        "path": str(fake_file),
        "sha256": session.target.sha256,
        "kind": "fake",
        "format": "fake",
        "arch": "toy",
    }
    assert ev.params == {"path": str(fake_file), "kind": None, "engine": None, "arch": None}


def test_same_list_twice_yields_the_same_id(bound: Session) -> None:
    a = invoke(bound, REGISTRY["list"], {"what": "things"})
    b = invoke(bound, REGISTRY["list"], {"what": "things", "match": None})
    assert a["evidence_id"] == b["evidence_id"]
    assert len(bound.ledger) == 1
    assert [x["name"] for x in a["result"]] == ["alpha", "beta", "gamma"]
    assert "page" not in a


def test_params_exclude_offset_and_limit(bound: Session) -> None:
    whole = invoke(bound, REGISTRY["list"], {"what": "things"})
    part = invoke(bound, REGISTRY["list"], {"what": "things", "offset": 1, "limit": 1})
    assert part["evidence_id"] == whole["evidence_id"]
    assert len(bound.ledger) == 1
    assert bound.ledger.get(part["evidence_id"]).params == {"what": "things", "match": None}
    assert [x["name"] for x in part["result"]] == ["beta"]
    assert part["page"] == {"unit": "items", "offset": 1, "next": 2, "total": 3}


def test_match_filters_and_changes_the_id(bound: Session) -> None:
    reply = invoke(bound, REGISTRY["list"], {"what": "things", "match": "ALPHA"})
    assert [x["name"] for x in reply["result"]] == ["alpha"]
    assert len(bound.ledger) == 1
    assert (
        reply["evidence_id"] != invoke(bound, REGISTRY["list"], {"what": "things"})["evidence_id"]
    )


def test_finding_sets_confidence_and_unknowns(bound: Session) -> None:
    reply = invoke(bound, REGISTRY["xrefs"], {"ref": "beta"})
    assert reply["confidence"] == "inferred"
    assert reply["unknowns"] == ["toy xref scan; no real control flow"]
    assert {x["type"] for x in reply["result"]} == {"call", "data"}
    assert set(reply["result"][0]) == {"ref", "name", "type", "at"}
    only_to = invoke(bound, REGISTRY["xrefs"], {"ref": "0x20", "direction": "to"})
    assert [x["name"] for x in only_to["result"]] == ["alpha"]


def test_iterator_results_are_listed(bound: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fake_kind, "list", lambda h, what, match=None: iter(fake_kind.THINGS))
    reply = invoke(bound, REGISTRY["list"], {"what": "things"})
    assert isinstance(bound.ledger.get(reply["evidence_id"]).result, list)
    assert len(reply["result"]) == 3


def test_show_views_and_bad_refs(bound: Session) -> None:
    reply = invoke(bound, REGISTRY["show"], {"ref": "0x30", "view": "info"})
    assert reply["result"] == {"name": "gamma", "ref": "0x30", "view": "info"}
    assert invoke(bound, REGISTRY["show"], {"ref": "alpha"})["result"]["view"] == "auto"
    fail(invoke, "not_found", bound, REGISTRY["show"], {"ref": "nope"})
    fail(invoke, "bad_input", bound, REGISTRY["show"], {"ref": "alpha", "view": "pseudo"})
    fail(invoke, "bad_input", bound, REGISTRY["list"], {"what": "functions"})
    fail(invoke, "bad_input", bound, REGISTRY["show"], {"ref": "0xzz"})


def test_missing_kind_function_is_unsupported(
    bound: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr(fake_kind, "xrefs")
    err = fail(invoke, "unsupported", bound, REGISTRY["xrefs"], {"ref": "alpha"})
    assert "fake" in err.message and "xrefs" in err.message


def test_open_failures(session: Session, tmp_path: Path) -> None:
    fail(invoke, "not_found", session, REGISTRY["open"], {"path": str(tmp_path / "missing")})
    other = tmp_path / "other.bin"
    other.write_bytes(b"not a fake target at all")
    fail(invoke, "unsupported", session, REGISTRY["open"], {"path": str(other), "kind": "nosuch"})
    assert session.target is None and len(session.ledger) == 0


def test_close_releases_the_handle(session: Session, fake_file: Path) -> None:
    fail(invoke, "not_found", session, REGISTRY["close"], {})
    invoke(session, REGISTRY["open"], {"path": str(fake_file)})
    handle = session.handle
    reply = invoke(session, REGISTRY["close"], {})
    assert reply["result"] == {"closed": str(fake_file)}
    assert reply["engine"] == "fake 1.0"  # the subject was captured before the close
    assert handle["open"] is False and session.target is None
    fail(invoke, "not_found", session, REGISTRY["list"], {"what": "things"})


def test_open_twice_closes_the_first(session: Session, fake_file: Path) -> None:
    invoke(session, REGISTRY["open"], {"path": str(fake_file)})
    first = session.handle
    invoke(session, REGISTRY["open"], {"path": str(fake_file), "engine": "fake 2.0"})
    assert first["open"] is False and session.handle["engine"] == "fake 2.0"


def test_second_open_records_the_new_target(session: Session, fake_file: Path, tmp_path) -> None:
    other = tmp_path / "other.bin"
    other.write_bytes(b"FAKE\x00other")
    invoke(session, REGISTRY["open"], {"path": str(fake_file)})
    reply = invoke(session, REGISTRY["open"], {"path": str(other), "engine": "fake 2.0"})
    ev = session.ledger.get(reply["evidence_id"])
    assert ev.subject["path"] == str(other) == session.target.path
    assert ev.subject["sha256"] == session.target.sha256
    assert ev.engine == reply["engine"] == "fake 2.0"


def test_url_open_is_unsupported_without_the_web_kind(session: Session) -> None:
    err = fail(invoke, "unsupported", session, REGISTRY["open"], {"path": "https://example.test"})
    assert "web" in err.message and "installed: fake" in err.hint
    assert session.target is None and len(session.ledger) == 0


def test_busy_session_fails_timeout(bound: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools, "LOCK_WAIT", 0.05)
    with bound.lock:
        err = fail(invoke, "timeout", bound, REGISTRY["list"], {"what": "things"})
    assert "another call" in err.message
    assert invoke(bound, REGISTRY["list"], {"what": "things"})["result"]


# --- evidence and doctor -----------------------------------------------------------


def test_evidence_lists_pages_exports_and_imports(bound: Session, tmp_path: Path) -> None:
    listed = invoke(bound, REGISTRY["list"], {"what": "things", "limit": 1})
    assert listed["page"]["next"] == 1
    eid = listed["evidence_id"]
    spec = REGISTRY["evidence"]
    index = invoke(bound, spec, {})
    assert index["count"] == 1 and index["records"][0] == {
        "id": eid,
        "op": "list",
        "params": {"what": "things", "match": None},
        "path": str(bound.target.path),
        "sha256": bound.target.sha256,
        "engine": "fake 1.0",
    }
    assert "page" not in index
    more = invoke(bound, spec, {"id": eid, "offset": 1, "limit": 1})
    assert [x["name"] for x in more["result"]] == ["beta"]
    assert more["page"] == {"unit": "items", "offset": 1, "next": 2, "total": 3}
    assert more["evidence_id"] == eid
    fail(invoke, "not_found", bound, spec, {"id": "ev_nope"})
    whole = invoke(bound, spec, {"id": eid})
    assert whole["result"] == invoke(bound, REGISTRY["list"], {"what": "things"})["result"]
    out = tmp_path / "out.jsonl"
    fail(invoke, "bad_input", bound, spec, {"export": str(out), "import": str(out)})
    assert invoke(bound, spec, {"export": str(out)}) == {"exported": 1, "path": str(out)}
    fail(invoke, "bad_input", bound, spec, {"export": str(out)})
    fresh = Session(Ledger())
    assert invoke(fresh, spec, {"import": str(out)}) == {"imported": 1, "path": str(out)}
    assert fresh.ledger.get(eid).result == bound.ledger.get(eid).result
    assert len(bound.ledger) == 1  # evidence records nothing


def test_evidence_listing_pages_by_item(bound: Session) -> None:
    for match in ("alpha", "beta", "gamma"):
        invoke(bound, REGISTRY["list"], {"what": "things", "match": match})
    spec = REGISTRY["evidence"]
    first = invoke(bound, spec, {"limit": 2})
    assert first["count"] == 3 and len(first["records"]) == 2
    assert first["page"] == {"unit": "items", "offset": 0, "next": 2, "total": 3}
    rest = invoke(bound, spec, {"offset": 2})
    assert [r["params"]["match"] for r in rest["records"]] == ["gamma"]
    assert rest["page"]["next"] is None
    fail(invoke, "bad_input", bound, spec, {"limit": 0})


def test_doctor_needs_no_target(session: Session, tmp_path: Path) -> None:
    reply = invoke(session, REGISTRY["doctor"], {})
    assert reply["engines"]["builtin"].startswith("lief ")
    assert set(reply["libraries"]) == {"mcp", "lief", "capstone", "psutil"}
    assert all(reply["libraries"][d] for d in ("mcp", "lief", "capstone"))
    assert set(P0_VERBS) <= set(reply["tools"])
    assert reply["skill"].endswith("skill/SKILL.md")
    assert reply["cache"] == str(tmp_path / "cache")
    assert set(reply["hints"]) <= set(tools.ENGINE_HINTS)
    assert len(session.ledger) == 0
