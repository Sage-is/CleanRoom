"""End to end: every P0 verb through ``uv run cleanroom`` on /bin/ls and the C fixture.

Each test runs its own subprocesses with CLEANROOM_CACHE and CLEANROOM_LEDGER under
tmp_path, so nothing touches ~/.cache/cleanroom and no test depends on another.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LS = Path("/bin/ls")
VERBS = ("open", "close", "list", "show", "xrefs", "evidence", "doctor")
XREF_TYPES = {"call", "jump", "data", "string", "import"}
REPLY_KEYS = {
    "evidence_id", "op", "engine", "confidence", "unknowns", "locations", "links", "result"
}  # fmt: skip
ASM_LINE = re.compile(r"^0x[0-9a-f]+: \S")

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="uv not on PATH")
darwin_only = pytest.mark.skipif(sys.platform != "darwin", reason="/bin/ls checks are macOS-only")


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    """A fresh cache and ledger per test; no engine override or test-kind hook leaks in."""
    base = {k: v for k, v in os.environ.items() if not k.startswith("CLEANROOM_")}
    base["CLEANROOM_CACHE"] = str(tmp_path / "cache")
    base["CLEANROOM_LEDGER"] = str(tmp_path / "ledger.jsonl")
    return base


def cli(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    argv = ["uv", "run", "cleanroom", *args]
    return subprocess.run(argv, capture_output=True, text=True, env=env, cwd=ROOT, timeout=60)


def ok(env: dict[str, str], *args: str) -> dict:
    done = cli(env, *args)
    assert done.returncode == 0, done.stderr or done.stdout
    return json.loads(done.stdout)


def reply(env: dict[str, str], *args: str) -> dict:
    """A verb reply: the Evidence shape with an ev_ id and a known confidence."""
    body = ok(env, *args)
    assert REPLY_KEYS <= set(body), sorted(body)
    assert body["evidence_id"].startswith("ev_") and len(body["evidence_id"]) == 67
    assert body["confidence"] in {"observed", "derived", "inferred"}
    assert body["engine"].startswith("builtin")
    return body


def fail(env: dict[str, str], *args: str) -> dict:
    done = cli(env, *args)
    assert done.returncode == 1, (done.stdout, done.stderr)
    body = json.loads(done.stdout)
    assert set(body) == {"error"} and {"code", "message"} <= set(body["error"])
    return body["error"]


def rejoin(env: dict[str, str], first: dict) -> list:
    """Follow ``page.next`` through ``evidence ID --offset N`` until it is null."""
    items = list(first["result"])
    page = first.get("page")
    while page and page["next"] is not None:
        more = reply(env, "evidence", first["evidence_id"], "--offset", str(page["next"]))
        assert more["evidence_id"] == first["evidence_id"] and more["op"] == first["op"]
        assert more["page"]["offset"] == page["next"] and more["page"]["unit"] == page["unit"]
        items.extend(more["result"])
        page = more.get("page")
    if first.get("page"):
        assert len(items) == first["page"]["total"]
    return items


def ledger_records(env: dict[str, str]) -> list[dict]:
    return [json.loads(ln) for ln in Path(env["CLEANROOM_LEDGER"]).read_text().splitlines()]


def test_open_fixture_reports_identity(env: dict[str, str], c_fixture: Path) -> None:
    body = reply(env, "open", str(c_fixture))
    r = body["result"]
    assert body["op"] == "open" and r["kind"] == "native"
    assert r["sha256"] == hashlib.sha256(c_fixture.read_bytes()).hexdigest()
    assert r["path"] == str(c_fixture) and r["size"] == c_fixture.stat().st_size
    assert r["engine"] == body["engine"] and r["format"] in {"macho", "elf"} and r["arch"]
    assert "functions" in r["list"] and {"asm", "bytes"} <= set(r["views"])
    assert "pseudo" not in r["views"]  # the builtin engine has no decompiler
    (record,) = ledger_records(env)
    assert record["id"] == body["evidence_id"] and record["op"] == "open"
    assert record["subject"]["sha256"] == r["sha256"] and record["subject"]["kind"] == "native"


@darwin_only
def test_open_ls_is_fat_native(env: dict[str, str]) -> None:
    r = reply(env, "open", str(LS))["result"]
    assert r["kind"] == "native" and r["format"] == "macho" and r["fat"] is True
    assert r["sha256"] == hashlib.sha256(LS.read_bytes()).hexdigest()
    assert len(r["slices"]) == 2 and r["arch"] in r["slices"]
    assert r["entry"].startswith("0x") and r["image_base"].startswith("0x")


def test_open_rejects_missing_and_unknown(env: dict[str, str], tmp_path: Path) -> None:
    assert fail(env, "open", str(tmp_path / "gone"))["code"] == "not_found"
    text = tmp_path / "notes.txt"
    text.write_text("just text, no magic\n")
    assert fail(env, "open", str(text))["code"] == "unsupported"
    assert fail(env, "list", "functions")["code"] == "not_found"


def test_close_reports_the_target(env: dict[str, str], c_fixture: Path) -> None:
    body = reply(env, "-t", str(c_fixture), "close")
    assert body["op"] == "close" and body["result"] == {"closed": str(c_fixture)}
    assert [r["op"] for r in ledger_records(env)] == ["open", "close"]


def test_list_functions_limit_pages_by_item(env: dict[str, str], c_fixture: Path) -> None:
    body = reply(env, "-t", str(c_fixture), "list", "functions", "--limit", "5")
    assert body["op"] == "list" and len(body["result"]) == 5
    page = body["page"]
    assert page["unit"] == "items" and page["offset"] == 0 and page["next"] == 5
    assert page["total"] >= 7
    for item in body["result"]:
        assert {"name", "address", "size"} <= set(item) and item["address"].startswith("0x")
    names = {f["name"] for f in rejoin(env, body)}
    assert {"_rea_leaf", "_rea_branch", "_rea_entry"} <= names or {
        "rea_leaf",
        "rea_branch",
    } <= names


@darwin_only
def test_list_functions_ls_limit_5(env: dict[str, str]) -> None:
    body = reply(env, "-t", str(LS), "list", "functions", "--limit", "5")
    assert len(body["result"]) == 5
    assert body["page"]["unit"] == "items" and body["page"]["next"] == 5
    assert body["page"]["total"] > 5


@darwin_only
def test_list_strings_ls_rejoins_through_evidence(env: dict[str, str]) -> None:
    first = reply(env, "-t", str(LS), "list", "strings", "--limit", "100000")
    assert "page" not in first or first["page"]["unit"] == "items"
    items = rejoin(env, first)
    assert any("PROGRAM:ls" in s.get("value", "") for s in items)
    assert all(s["address"].startswith("0x") and s["section"] for s in items)


def test_list_strings_pages_rejoin_exactly(env: dict[str, str], c_fixture: Path) -> None:
    whole = reply(env, "-t", str(c_fixture), "list", "strings", "--limit", "100000")
    all_items = rejoin(env, whole)
    first = reply(env, "-t", str(c_fixture), "list", "strings", "--limit", "3")
    assert first["evidence_id"] == whole["evidence_id"], "offset/limit are not part of the id"
    assert first["page"]["next"] == 3 and len(first["result"]) == 3
    assert rejoin(env, first) == all_items
    values = [s.get("value") for s in all_items]
    assert "REA_C_LEAF" in values and any(v and v.endswith("needle") for v in values)


def test_list_match_filters(env: dict[str, str], c_fixture: Path) -> None:
    body = reply(env, "-t", str(c_fixture), "list", "functions", "--match", "rea_cycle")
    assert {f["name"].lstrip("_") for f in body["result"]} == {"rea_cycle_a", "rea_cycle_b"}
    assert "page" not in body
    assert fail(env, "-t", str(c_fixture), "list", "nonsense")["code"] == "bad_input"


def test_show_asm_lists_instructions(env: dict[str, str], c_fixture: Path) -> None:
    body = reply(env, "-t", str(c_fixture), "show", "rea_leaf", "--view", "asm")
    assert body["op"] == "show" and isinstance(body["result"], str)
    lines = body["result"].splitlines()
    assert len(lines) >= 4 and all(ASM_LINE.match(ln) for ln in lines), lines[:3]
    info = reply(env, "-t", str(c_fixture), "show", "rea_leaf", "--view", "info")["result"]
    assert info["address"] == lines[0].split(":")[0]


@darwin_only
def test_show_entry_asm_ls(env: dict[str, str]) -> None:
    entry = reply(env, "open", str(LS))["result"]["entry"]
    body = reply(env, "-t", str(LS), "show", entry, "--view", "asm")
    assert body["result"].startswith(entry + ": ")
    assert body["result"].count("\n") > 10


def test_show_pseudo_is_unsupported_on_builtin(env: dict[str, str], c_fixture: Path) -> None:
    err = fail(env, "-t", str(c_fixture), "show", "rea_leaf", "--view", "pseudo")
    assert err["code"] == "unsupported"
    assert "ghidra" in (err.get("hint") or "").lower()
    assert fail(env, "-t", str(c_fixture), "show", "no_such_symbol")["code"] == "not_found"


def test_xrefs_to_leaf_names_branch(env: dict[str, str], c_fixture: Path) -> None:
    body = reply(env, "-t", str(c_fixture), "xrefs", "rea_leaf", "--direction", "to")
    assert body["op"] == "xrefs" and body["result"]
    assert {x["name"].lstrip("_") for x in body["result"]} == {"rea_branch"}
    for item in body["result"]:
        assert {"ref", "name", "type", "at"} <= set(item) and item["type"] == "call"
        assert item["ref"].startswith("0x") and item["at"].startswith("0x")
    both = reply(env, "-t", str(c_fixture), "xrefs", "rea_branch")
    assert {x["type"] for x in both["result"]} <= XREF_TYPES
    assert {x["name"].lstrip("_") for x in both["result"]} >= {"rea_leaf", "rea_entry"}


@darwin_only
def test_xrefs_from_entry_ls_sees_imports(env: dict[str, str]) -> None:
    entry = reply(env, "open", str(LS))["result"]["entry"]
    body = reply(env, "-t", str(LS), "xrefs", entry, "--direction", "from")
    types = {x["type"] for x in body["result"]}
    assert "import" in types and types <= XREF_TYPES
    assert any(x["type"] == "import" and x["name"].startswith("_") for x in body["result"])
    assert fail(env, "-t", str(LS), "xrefs", "0x1", "--direction", "to")["code"] == "not_found"


def test_doctor_lists_engines_libraries_and_hints(env: dict[str, str]) -> None:
    body = ok(env, "doctor")
    assert "evidence_id" not in body
    assert (
        body["engines"]["builtin"].startswith("lief ") and "capstone" in body["engines"]["builtin"]
    )
    for lib in ("lief", "capstone", "mcp", "psutil"):
        assert re.match(r"\d+\.\d+", body["libraries"][lib] or ""), lib
    if body["engines"]["ghidra"] is None:
        assert "GHIDRA_INSTALL_DIR" in body["hints"]["ghidra"]
    assert "native" in body["kinds"] and set(VERBS) <= set(body["tools"])
    assert body["ledger"] == env["CLEANROOM_LEDGER"] and body["cache"] == env["CLEANROOM_CACHE"]
    assert body["skill"].endswith("SKILL.md") and Path(body["skill"]).is_file()
    assert body["python"].startswith("3.") and body["version"]


def test_evidence_lists_recorded_ids(env: dict[str, str], c_fixture: Path) -> None:
    listed = reply(env, "-t", str(c_fixture), "list", "imports")
    shown = reply(env, "-t", str(c_fixture), "show", "rea_leaf", "--view", "bytes")
    body = ok(env, "evidence")
    assert "evidence_id" not in body and body["ledger"] == env["CLEANROOM_LEDGER"]
    ids = [r["id"] for r in body["records"]]
    assert body["count"] == len(ids) == 3, "the second open of the same file is a no-op"
    assert all(i.startswith("ev_") for i in ids) and len(set(ids)) == 3
    assert [r["op"] for r in body["records"]] == ["open", "list", "show"]
    assert listed["evidence_id"] in ids and shown["evidence_id"] in ids
    assert body["records"][1]["params"] == {"what": "imports", "match": None}
    again = reply(env, "evidence", shown["evidence_id"])
    assert again["result"] == shown["result"] and again["op"] == "show"
    assert fail(env, "evidence", "ev_" + "0" * 64)["code"] == "not_found"


def test_evidence_export_import_round_trips(
    env: dict[str, str], c_fixture: Path, tmp_path: Path
) -> None:
    reply(env, "-t", str(c_fixture), "xrefs", "rea_branch", "--direction", "from")
    out = tmp_path / "export.jsonl"
    exported = ok(env, "evidence", "--export", str(out))
    assert exported == {"exported": 2, "path": str(out)} and out.is_file()
    assert fail(env, "evidence", "--export", str(out))["code"] == "bad_input"
    fresh = {**env, "CLEANROOM_LEDGER": str(tmp_path / "fresh.jsonl")}
    assert ok(fresh, "evidence", "--import", str(out))["imported"] == 2
    listing = ok(fresh, "evidence")
    assert listing["count"] == 2 and [r["op"] for r in listing["records"]] == ["open", "xrefs"]
    assert listing["records"] == ok(env, "evidence")["records"]
    xid = listing["records"][1]["id"]
    again = reply(fresh, "evidence", xid)
    assert again["evidence_id"] == xid and again["op"] == "xrefs" and again["result"]
    tampered = tmp_path / "tampered.jsonl"
    tampered.write_text(out.read_text().replace('"xrefs"', '"xrefz"'))
    third = {**env, "CLEANROOM_LEDGER": str(tmp_path / "third.jsonl")}
    assert fail(third, "evidence", "--import", str(tampered))["code"] == "bad_input"
