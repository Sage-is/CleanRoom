"""graph.py: trace (xref BFS) and diff (keyed inventories) over the compiled fixtures.

The fixtures are Mach-O FAT on macOS and ELF elsewhere; ``sym`` adds the Mach-O
underscore so one assertion serves both. The fake kind covers the generic paths that
need no compiler.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import cleanroom.graph  # noqa: F401 - registers trace and diff
from cleanroom.evidence import Evidence, Ledger
from cleanroom.target import Fail
from cleanroom.tools import REGISTRY, Session, invoke, schema
from tests.fixtures import fake_kind

ROOT = Path(__file__).resolve().parent.parent
LS = "/bin/ls"


def sym(name: str) -> str:
    return "_" + name if sys.platform == "darwin" else name


@pytest.fixture(autouse=True)
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CLEANROOM_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("CLEANROOM_LEDGER", str(tmp_path / "ledger.jsonl"))


@pytest.fixture
def session(tmp_path: Path) -> Session:
    return Session(Ledger(str(tmp_path / "ledger.jsonl")))


def run(session: Session, verb: str, **args) -> dict:
    return invoke(session, REGISTRY[verb], args)


def opened(session: Session, path: Path | str) -> Session:
    run(session, "open", path=str(path))
    return session


def fail(code: str, session: Session, verb: str, **args) -> Fail:
    with pytest.raises(Fail) as info:
        run(session, verb, **args)
    assert info.value.code == code, str(info.value)
    return info.value


@pytest.fixture
def fx(session: Session, c_fixture: Path) -> Session:
    return opened(session, c_fixture)


def names_along(reply: dict) -> list[str]:
    by_ref = {n["ref"]: n["name"] for n in reply["result"]["nodes"]}
    return [by_ref[r] for r in reply["result"]["path"]]


# --- registry ---------------------------------------------------------------------


def test_registry_has_trace_and_diff() -> None:
    trace, diff = REGISTRY["trace"], REGISTRY["diff"]
    assert trace.needs_target and trace.records and trace.read_only
    assert not diff.needs_target and not diff.records and diff.read_only
    assert schema(trace)["required"] == ["start"]
    assert list(schema(trace)["properties"]) == ["start", "goal", "depth", "max_nodes"]
    assert schema(trace)["properties"]["depth"]["default"] == 3
    assert schema(trace)["properties"]["max_nodes"]["default"] == 500
    assert schema(diff)["required"] == ["a", "b"]
    assert list(schema(diff)["properties"]) == ["a", "b", "what"]


def test_main_module_registers_graph() -> None:
    text = (ROOT / "cleanroom" / "__main__.py").read_text(encoding="utf-8")
    assert "import cleanroom.graph" in text


# --- trace on the compiled fixture ------------------------------------------------


def test_trace_finds_shortest_path(fx: Session) -> None:
    reply = run(fx, "trace", start="rea_entry", goal="rea_leaf")
    res = reply["result"]
    assert res["found"] is True and res["truncated"] is False
    assert names_along(reply) == [sym("rea_entry"), sym("rea_branch"), sym("rea_leaf")]
    assert res["start"].startswith("0x") and res["goal"].startswith("0x")
    assert res["nodes"][0] == {"ref": res["start"], "name": sym("rea_entry")}
    assert res["path"][0] == res["start"] and res["path"][-1] == res["goal"]
    assert {(e["from"], e["to"], e["type"]) for e in res["edges"]} >= {
        (res["path"][0], res["path"][1], "call"),
        (res["path"][1], res["path"][2], "call"),
    }
    assert reply["confidence"] == "derived" and reply["links"] == [] and reply["unknowns"] == []
    assert reply["op"] == "trace" and "page" not in reply
    assert fx.ledger.get(reply["evidence_id"]).params == {
        "start": "rea_entry",
        "goal": "rea_leaf",
        "depth": 3,
        "max_nodes": 500,
    }


def test_trace_cycle_terminates(fx: Session) -> None:
    reply = run(fx, "trace", start="rea_cycle_a", depth=10)
    res = reply["result"]
    assert res["found"] is False and res["goal"] is None and res["path"] == []
    assert res["truncated"] is False
    assert [n["name"] for n in res["nodes"]] == [sym("rea_cycle_a"), sym("rea_cycle_b")]
    a, b = (n["ref"] for n in res["nodes"])
    assert res["edges"] == [
        {"from": a, "to": b, "type": "call"},
        {"from": b, "to": a, "type": "call"},
    ]


def test_trace_max_nodes_truncates(fx: Session) -> None:
    reply = run(fx, "trace", start="rea_entry", max_nodes=2)
    assert reply["result"]["truncated"] is True
    assert len(reply["result"]["nodes"]) == 2
    assert "truncated at max_nodes" in reply["unknowns"]


def test_trace_data_goal_follows_string_edges(fx: Session) -> None:
    strings = run(fx, "list", what="strings", match="REA_C_LEAF")["result"]
    assert len(strings) == 1
    reply = run(fx, "trace", start="rea_entry", goal=strings[0]["address"])
    res = reply["result"]
    assert res["found"] is True
    assert names_along(reply)[:3] == [sym("rea_entry"), sym("rea_branch"), sym("rea_leaf")]
    assert res["path"][-1] == strings[0]["address"]
    last = [e for e in res["edges"] if e["to"] == strings[0]["address"]]
    assert last and last[0]["type"] == "string"
    assert reply["unknowns"][0].endswith("data and string edges were followed")


def test_trace_without_goal_walks_calls_only(fx: Session) -> None:
    res = run(fx, "trace", start="rea_leaf")["result"]
    assert {e["type"] for e in res["edges"]} <= {"call", "jump", "import"}
    assert sym("puts") in {n["name"] for n in res["nodes"]}


def test_trace_depth_limit_is_an_unknown(fx: Session) -> None:
    reply = run(fx, "trace", start="rea_entry", goal="rea_leaf", depth=1)
    assert reply["result"]["found"] is False
    assert any(u.startswith("depth 1 reached") for u in reply["unknowns"])
    assert sym("rea_branch") in {n["name"] for n in reply["result"]["nodes"]}


def test_trace_goal_equal_to_start(fx: Session) -> None:
    res = run(fx, "trace", start="rea_entry", goal="rea_entry")["result"]
    assert res["found"] is True and res["path"] == [res["start"]]


def test_trace_errors(session: Session, c_fixture: Path) -> None:
    assert "no target open" in fail("not_found", session, "trace", start="rea_entry").message
    opened(session, c_fixture)
    fail("not_found", session, "trace", start="no_such_function")
    fail("bad_input", session, "trace", start="rea_entry", depth=-1)
    fail("bad_input", session, "trace", start="rea_entry", max_nodes=0)


def test_trace_over_the_fake_kind(session: Session, tmp_path: Path) -> None:
    toy = tmp_path / "toy.bin"
    toy.write_bytes(b"FAKE\x00toy")
    t = fake_target(toy)
    session.bind(t, fake_kind, fake_kind.open(t))
    reply = run(session, "trace", start="alpha")
    assert reply["result"]["nodes"] == [{"ref": "0x10", "name": "alpha"}]
    assert reply["result"]["edges"] == [] and reply["result"]["found"] is False
    reply = run(session, "trace", start="alpha", goal="nothing")
    res = reply["result"]
    assert [n["name"] for n in res["nodes"]] == ["alpha", "gamma"]
    assert res["edges"] == [{"from": "0x10", "to": "0x30", "type": "data"}]
    assert res["found"] is False
    assert "toy xref scan; no real control flow" in reply["unknowns"]
    assert reply["unknowns"][0].startswith("nothing is not a function here")
    assert reply["engine"] == "fake 1.0"


def fake_target(path: Path):
    from cleanroom.target import Target, sha256_file

    return Target(str(path), sha256_file(str(path)), path.stat().st_size, "fake")


# --- diff -------------------------------------------------------------------------


def test_diff_two_paths(session: Session, c_v1: Path, c_v2: Path) -> None:
    opened(session, c_v1)
    reply = run(session, "diff", a=str(c_v1), b=str(c_v2))
    res, cats = reply["result"], reply["result"]["categories"]
    assert res["status"] == "changed" and res["kind"] == "native"
    assert res["a"]["path"] == str(c_v1) and res["b"]["path"] == str(c_v2)
    assert res["a"]["sha256"] != res["b"]["sha256"]
    fn = cats["functions"]
    assert fn["added"] == [sym("rea_added")] and fn["removed"] == []
    assert {sym("rea_version_leaf"), sym("rea_version_entry")} <= set(fn["changed"])
    assert fn["status"] == "changed"
    assert "REA_VERSION_TWO" in cats["strings"]["added"]
    assert "REA_VERSION_ONE" in cats["strings"]["removed"]
    assert cats["sections"]["status"] == "unchanged" and cats["sections"]["unchanged"] > 0
    assert set(cats) == set(session.kind.DIFF_KEYS)
    assert reply["confidence"] == "derived" and reply["unknowns"] == []
    assert len(reply["links"]) == 2 * len(cats)
    for eid in reply["links"]:
        ev = session.ledger.get(eid)
        assert ev.op == "list" and ev.subject["path"] in (str(c_v1), str(c_v2))
    me = session.ledger.get(reply["evidence_id"])
    assert me.op == "diff" and me.subject is None and me.engine == "cleanroom"
    assert me.params == {"a": str(c_v1), "b": str(c_v2), "what": None}
    assert session.target.path == str(c_v1)
    assert run(session, "list", what="functions")["result"]


def test_diff_what_limits_the_categories(session: Session, c_v1: Path, c_v2: Path) -> None:
    reply = run(session, "diff", a=str(c_v1), b=str(c_v2), what="functions")
    assert list(reply["result"]["categories"]) == ["functions"]
    assert reply["result"]["categories"]["functions"]["added"] == [sym("rea_added")]
    assert len(reply["links"]) == 2
    assert session.target is None


@pytest.mark.skipif(not os.path.isfile(LS), reason="no /bin/ls")
def test_diff_same_file_is_unchanged(session: Session) -> None:
    reply = run(session, "diff", a=LS, b=LS)
    res = reply["result"]
    assert res["status"] == "unchanged"
    for cat, report in res["categories"].items():
        assert report["status"] == "unchanged", cat
        assert report["added"] == [] and report["removed"] == [] and report["changed"] == []
        unkeyed = report.get("unkeyed", [0, 0])
        assert unkeyed[0] == unkeyed[1]
    assert reply["unknowns"] == []


def test_diff_two_ids(session: Session, c_v1: Path, c_v2: Path) -> None:
    opened(session, c_v1)
    id1 = run(session, "list", what="functions")["evidence_id"]
    opened(session, c_v2)
    id2 = run(session, "list", what="functions")["evidence_id"]
    reply = run(session, "diff", a=id1, b=id2)
    fn = reply["result"]["categories"]["functions"]
    assert fn["added"] == [sym("rea_added")] and fn["removed"] == []
    assert fn["changed"] == []  # no handle behind an id, so no asm to compare
    assert fn["unchanged"] > 0 and fn["status"] == "changed"
    assert reply["links"] == [id1, id2]
    assert reply["result"]["a"]["path"] == str(c_v1)
    assert reply["unknowns"] == [
        "functions: only listed fields compared; pass paths to diff to compare asm bodies"
    ]
    same = run(session, "diff", a=id1, b=id1)
    assert same["result"]["status"] == "unchanged" and same["unknowns"] == []
    mixed = run(session, "diff", a=id1, b=str(c_v2))
    assert mixed["result"]["categories"]["functions"]["added"] == [sym("rea_added")]
    assert mixed["links"][0] == id1 and len(mixed["links"]) == 2
    assert session.target.path == str(c_v2)


def test_diff_truncated_side_is_unknown(session: Session, c_v1: Path, c_v2: Path) -> None:
    opened(session, c_v1)
    full = session.ledger.get(run(session, "list", what="functions")["evidence_id"])
    cut = Evidence(
        full.op,
        full.params,
        full.subject,
        full.engine,
        full.result[:1],
        "observed",
        ("stopped at limit 1",),
    )
    session.ledger.record(cut)
    opened(session, c_v2)
    id2 = run(session, "list", what="functions")["evidence_id"]
    reply = run(session, "diff", a=cut.id, b=id2)
    fn = reply["result"]["categories"]["functions"]
    assert fn["status"] == "unknown" and reply["result"]["status"] == "unknown"
    assert "added" not in fn and "removed" not in fn
    assert fn["changed"] == [] and fn["unchanged"] == 1
    assert reply["unknowns"][0] == "functions: a is incomplete: stopped at limit 1"
    assert reply["unknowns"][1].startswith("functions: only listed fields compared")
    assert reply["links"] == [cut.id, id2]


def test_diff_same_listed_fields_on_different_files_is_unknown(
    session: Session, c_v1: Path, c_v2: Path
) -> None:
    """An ev/ev diff cannot read bodies, so agreeing fields are not an unchanged claim."""
    opened(session, c_v1)
    id1 = run(session, "list", what="sections")["evidence_id"]
    opened(session, c_v2)
    id2 = run(session, "list", what="sections")["evidence_id"]
    reply = run(session, "diff", a=id1, b=id2)
    assert reply["result"]["categories"]["sections"]["status"] == "unchanged"  # no probe view
    assert reply["unknowns"] == []
    fid1 = run(session, "list", what="functions", match="rea_version_leaf")["evidence_id"]
    err = fail("bad_input", session, "diff", a=fid1, b=id2)
    assert "filtered list" in err.message and "rea_version_leaf" in err.message


def test_diff_all_unkeyed_sides_are_unknown(session: Session) -> None:
    def rec(path: str, addrs: list[str]) -> Evidence:
        items = [{"name": "", "address": a, "size": 4} for a in addrs]
        subject = {"path": path, "sha256": path * 8, "kind": "native"}
        return Evidence(
            "list", {"what": "functions", "match": None}, subject, "x", items, "observed"
        )

    a, b = rec("/a", ["0x10", "0x20"]), rec("/b", ["0x30", "0x40"])
    session.ledger.record(a)
    session.ledger.record(b)
    reply = run(session, "diff", a=a.id, b=b.id)
    fn = reply["result"]["categories"]["functions"]
    assert fn["unkeyed"] == [2, 2] and fn["status"] == "unknown"
    assert reply["result"]["status"] == "unknown"
    assert "functions: 2 and 2 unkeyed items were not compared" in reply["unknowns"]
    same = run(session, "diff", a=a.id, b=a.id)
    assert same["result"]["status"] == "unchanged"


def test_diff_detects_path_kinds_instead_of_the_bound_one(
    session: Session, c_v1: Path, c_v2: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "cleanroom.kinds.fake", fake_kind)
    toy = tmp_path / "toy.bin"
    toy.write_bytes(b"FAKE\x00toy")
    t = fake_target(toy)
    session.bind(t, fake_kind, fake_kind.open(t))
    reply = run(session, "diff", a=str(c_v1), b=str(c_v2), what="functions")
    assert reply["result"]["kind"] == "native"
    assert reply["result"]["categories"]["functions"]["added"] == [sym("rea_added")]
    assert session.target.path == str(toy)


def test_trace_goal_import_without_underscore(fx: Session) -> None:
    reply = run(fx, "trace", start="rea_leaf", goal="puts")
    assert reply["result"]["found"] is True
    assert names_along(reply)[-1] == sym("puts")


def test_diff_errors(session: Session, c_v1: Path, tmp_path: Path) -> None:
    opened(session, c_v1)
    fns = run(session, "list", what="functions")["evidence_id"]
    strs = run(session, "list", what="strings")["evidence_id"]
    shown = run(session, "show", ref="rea_version_leaf", view="info")["evidence_id"]
    mismatch = fail("bad_input", session, "diff", a=fns, b=strs).message
    assert mismatch == "the sides do not match: a native functions; b native strings"
    assert (
        "lists functions, not strings"
        in fail("bad_input", session, "diff", a=fns, b=fns, what="strings").message
    )
    assert "show record" in fail("bad_input", session, "diff", a=shown, b=fns).message
    fail("not_found", session, "diff", a="ev_" + "0" * 64, b=fns)
    fail("not_found", session, "diff", a=str(tmp_path / "missing"), b=str(c_v1))
    fail("bad_input", session, "diff", a=str(c_v1), b=str(c_v1), what="bogus")
    assert session.target.path == str(c_v1)


# --- command line -----------------------------------------------------------------


def cli_env(tmp_path: Path) -> dict[str, str]:
    return {
        **os.environ,
        "CLEANROOM_CACHE": str(tmp_path / "cache"),
        "CLEANROOM_LEDGER": str(tmp_path / "ledger.jsonl"),
    }


def test_cli_trace(tmp_path: Path, c_fixture: Path) -> None:
    argv = [sys.executable, "-m", "cleanroom", "-t", str(c_fixture), "trace", "rea_entry"]
    argv += ["--goal", "rea_leaf"]
    done = subprocess.run(argv, capture_output=True, text=True, env=cli_env(tmp_path), cwd=ROOT)
    assert done.returncode == 0, done.stderr
    body = json.loads(done.stdout)
    assert body["op"] == "trace" and body["result"]["found"] is True
    assert len(body["result"]["path"]) == 3
    assert not (tmp_path / "cache" / "ledger.jsonl").exists()
    assert (tmp_path / "ledger.jsonl").is_file()


def test_cli_diff_with_uv(tmp_path: Path, c_v1: Path, c_v2: Path) -> None:
    if shutil.which("uv") is None:
        pytest.skip("uv not on PATH")
    argv = ["uv", "run", "cleanroom", "-t", str(c_v1), "diff", str(c_v1), str(c_v2)]
    argv += ["--what", "functions"]
    done = subprocess.run(
        argv, capture_output=True, text=True, env=cli_env(tmp_path), cwd=ROOT, timeout=180
    )
    assert done.returncode == 0, done.stderr
    body = json.loads(done.stdout)
    assert body["op"] == "diff" and body["result"]["status"] == "changed"
    assert body["result"]["categories"]["functions"]["added"] == [sym("rea_added")]
    assert len(body["links"]) == 2


def test_cli_diff_help_and_catalog(tmp_path: Path) -> None:
    env = cli_env(tmp_path)
    done = subprocess.run(
        [sys.executable, "-m", "cleanroom", "diff", "--help"],
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
    )
    assert done.returncode == 0 and "--what" in done.stdout and " a " in done.stdout
    done = subprocess.run(
        [sys.executable, "-m", "cleanroom", "catalog"], capture_output=True, text=True, env=env
    )
    names = {t["name"] for t in json.loads(done.stdout)["tools"]}
    assert {"trace", "diff"} <= names
