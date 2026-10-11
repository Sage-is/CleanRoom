"""P0.3: Evidence ids, the ledger, JSONL round trips and paging."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from cleanroom.evidence import PAGE_BYTES, Evidence, Finding, Ledger, canonical, page
from cleanroom.target import Fail

SUBJ = {
    "path": "/bin/ls",
    "sha256": "0" * 64,
    "kind": "native",
    "format": "macho",
    "arch": "arm64",
}
ENGINE = "lief 1.0.0 + capstone 5.0.9"
# Pinned on 2026-10-10: a different value here means ids changed across versions.
PINNED_ID = "ev_d830606caa9070e2e49cae8951f2c744873de487657aee4cffc117367910bef9"


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLEANROOM_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("CLEANROOM_LEDGER", str(tmp_path / "ledger.jsonl"))


DEFAULT = {"name": "_rea_leaf", "asm": ["ret"]}


def ev(result=DEFAULT, **kw) -> Evidence:
    base = dict(
        op="show",
        params={"ref": "_rea_leaf", "view": "asm"},
        subject=SUBJ,
        engine=ENGINE,
        result=result,
        confidence="observed",
        unknowns=("x",),
        locations=("0x100003f20",),
        links=(),
    )
    return Evidence(**{**base, **kw})


def walk(e: Evidence, limit=None):
    """Follow offset/next until the end; return (pages, replies)."""
    replies, offset = [], 0
    while offset is not None:
        r = page(e, offset, limit)
        replies.append(r)
        assert len(canonical(r["result"])) <= PAGE_BYTES + 2
        offset = r["page"]["next"]
    return replies


# --- ids and canonical -------------------------------------------------------


def test_id_is_stable_and_pinned():
    assert ev().id == PINNED_ID
    assert ev().id == ev().id
    assert Evidence(**{**ev().__dict__, "unknowns": ["x"]}).id == PINNED_ID  # list == tuple


def test_every_field_changes_the_id():
    base = ev()
    changes = dict(
        op="list",
        params={"ref": "_rea_leaf", "view": "bytes"},
        subject=None,
        engine="ghidra 12.0.1",
        result={"name": "_rea_leaf", "asm": ["nop"]},
        confidence="derived",
        unknowns=("y",),
        locations=("0x100003f24",),
        links=("ev_0",),
    )
    seen = {base.id}
    for k, v in changes.items():
        seen.add(replace(base, **{k: v}).id)
    assert len(seen) == len(changes) + 1


def test_params_offset_does_not_matter_when_stripped():
    # tools.py strips offset/limit before building the record; the id then matches.
    assert ev(params={"what": "functions"}).id == ev(params={"what": "functions"}).id


def test_canonical_rejects_nan_and_non_json():
    for bad in (float("nan"), float("inf"), {"a": float("nan")}, b"bytes", {1, 2}):
        with pytest.raises(Fail) as e:
            canonical(bad)
        assert e.value.code == "bad_input"
    with pytest.raises(Fail):
        _ = ev(result={"n": float("nan")}).id


def test_canonical_is_sorted_compact_utf8():
    assert canonical({"b": 1, "a": "é😀"}) == '{"a":"é😀","b":1}'.encode()


def test_evidence_validates_confidence_and_normalises_tuples():
    with pytest.raises(Fail) as e:
        ev(confidence="unknown")
    assert e.value.code == "bad_input"
    assert ev(links=["ev_1"]).links == ("ev_1",)


def test_finding_shape():
    f = Finding([1], "inferred", ("no symbols",))
    assert (f.value, f.confidence, f.unknowns) == ([1], "inferred", ("no symbols",))


# --- ledger ------------------------------------------------------------------


def test_record_twice_is_a_noop():
    led = Ledger()
    a = led.record(ev())
    b = led.record(ev())
    assert a == b == PINNED_ID and len(led) == 1
    assert led.get(a) == ev()


def test_get_missing_is_not_found():
    with pytest.raises(Fail) as e:
        Ledger().get("ev_nope")
    assert e.value.code == "not_found"


def test_same_id_different_content_fails():
    led = Ledger()
    eid = led.record(ev())
    led._records[eid] = ev(result="forged")  # only a hash collision could do this
    with pytest.raises(Fail) as e:
        led.record(ev())
    assert e.value.code == "failed"


def test_persistent_ledger_reloads(tmp_path: Path):
    path = tmp_path / "deep" / "ledger.jsonl"
    led = Ledger(str(path))
    a = led.record(ev())
    b = led.record(ev(op="list", result=[1, 2]))
    led.record(ev())  # no second line
    assert path.read_text().count("\n") == 2
    again = Ledger(str(path))
    assert len(again) == 2
    assert again.get(a) == ev() and again.get(b) == ev(op="list", result=[1, 2])
    assert again.get(a).unknowns == ("x",)  # tuples survive the JSON round trip
    assert [e.id for e in again] == [a, b]


def test_tampered_line_is_rejected(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    Ledger(str(path)).record(ev(result="leaf"))
    path.write_text(path.read_text().replace("leaf", "leag"))
    with pytest.raises(Fail) as e:
        Ledger(str(path))
    assert e.value.code == "bad_input"
    fresh = Ledger()
    with pytest.raises(Fail) as e:
        fresh.import_(str(path))
    assert e.value.code == "bad_input" and len(fresh) == 0


def test_torn_last_line_is_cut_and_the_ledger_keeps_working(tmp_path: Path, capsys):
    """A process killed mid-append leaves a partial line; the session ledger repairs it."""
    path = tmp_path / "ledger.jsonl"
    led = Ledger(str(path))
    a = led.record(ev())
    whole = path.read_bytes()
    path.write_bytes(whole + b'{"id": "ev_torn", "op": "li')
    again = Ledger(str(path))
    assert [e.id for e in again] == [a]
    assert path.read_bytes() == whole
    assert "torn last line" in capsys.readouterr().err
    b = again.record(ev(op="list", result=[1]))
    assert [e.id for e in Ledger(str(path))] == [a, b]
    fresh = Ledger()
    path.write_bytes(whole + b"not json")
    with pytest.raises(Fail) as e:  # import stays strict: a torn line rejects the file
        fresh.import_(str(path))
    assert e.value.code == "bad_input" and len(fresh) == 0


def test_whole_last_line_without_newline_gets_one(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    led = Ledger(str(path))
    a = led.record(ev())
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    again = Ledger(str(path))
    assert [e.id for e in again] == [a] and path.read_bytes().endswith(b"\n")
    b = again.record(ev(op="list", result=[1]))
    assert [e.id for e in Ledger(str(path))] == [a, b]


def test_import_refuses_non_files_and_huge_files(tmp_path: Path, monkeypatch):
    with pytest.raises(Fail) as e:
        Ledger().import_(str(tmp_path))
    assert e.value.code == "not_found"
    path = tmp_path / "big.jsonl"
    Ledger(str(path)).record(ev())
    monkeypatch.setattr("cleanroom.evidence.MAX_FILE", 10)
    with pytest.raises(Fail) as e:
        Ledger().import_(str(path))
    assert e.value.code == "too_big"


def test_garbage_line_is_rejected(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    path.write_text('{"id": "ev_x", "op": 1}\n')
    with pytest.raises(Fail) as e:
        Ledger(str(path))
    assert e.value.code == "bad_input"
    path.write_text("not json\n")
    with pytest.raises(Fail):
        Ledger(str(path))


def test_export_import_round_trip(tmp_path: Path):
    led = Ledger()
    led.record(ev())
    led.record(ev(op="list", result=[{"i": 1}]))
    out = tmp_path / "bundle.jsonl"
    assert led.export(str(out)) == 2
    with pytest.raises(Fail) as e:
        led.export(str(out))
    assert e.value.code == "bad_input"
    assert led.export(str(out), overwrite=True) == 2
    fresh = Ledger()
    assert fresh.import_(str(out)) == 2
    assert fresh.import_(str(out)) == 0
    assert {e.id for e in fresh} == {e.id for e in led}
    with pytest.raises(Fail) as e:
        fresh.import_(str(tmp_path / "missing.jsonl"))
    assert e.value.code == "not_found"


# --- paging ------------------------------------------------------------------


def test_small_result_has_no_page_key():
    r = page(ev())
    assert "page" not in r
    assert r["result"] == {"name": "_rea_leaf", "asm": ["ret"]}
    assert r["evidence_id"] == PINNED_ID
    assert set(r) == {
        "evidence_id",
        "op",
        "engine",
        "confidence",
        "unknowns",
        "locations",
        "links",
        "result",
    }
    assert page(ev(result=[1, 2, 3]))["result"] == [1, 2, 3]
    assert page(ev(result="short"))["result"] == "short"
    assert page(ev(result=None))["result"] is None


def test_list_pages_rejoin_exactly():
    items = [
        {"i": i, "name": f"_rea_fn_{i}", "addr": f"0x{0x100000000 + 4 * i:x}"} for i in range(5000)
    ]
    replies = walk(ev(op="list", result=items))
    assert len(replies) > 1
    got = [x for r in replies for x in r["result"]]
    assert got == items
    assert replies[0]["page"] == {
        "unit": "items",
        "offset": 0,
        "next": len(replies[0]["result"]),
        "total": 5000,
    }
    assert replies[-1]["page"]["next"] is None
    assert all(
        r["page"]["offset"] + len(r["result"]) == (r["page"]["next"] or 5000) for r in replies
    )


def test_limit_cuts_a_list():
    items = [{"i": i} for i in range(5000)]
    r = page(ev(result=items), 0, 10)
    assert r["result"] == items[:10]
    assert r["page"] == {"unit": "items", "offset": 0, "next": 10, "total": 5000}
    r = page(ev(result=items), 4995, 10)
    assert r["result"] == items[4995:] and r["page"]["next"] is None
    assert page(ev(result=items[:10]), 0, 10).get("page") is None  # nothing was cut
    assert page(ev(result=items[:10]), 20)["result"] == []
    with pytest.raises(Fail) as e:  # limit 0 would make next == offset: a client would loop
        page(ev(result=items[:10]), 0, 0)
    assert e.value.code == "bad_input"


def test_string_pages_never_split_a_code_point():
    text = "é😀" * 34000  # about 204 KB of UTF-8
    replies = walk(ev(op="show", result=text))
    assert len(replies) >= 4
    for r in replies:
        chunk = r["result"]
        assert chunk and r["page"]["unit"] == "chars"
        assert chunk.encode("utf-8").decode("utf-8") == chunk
        assert set(chunk) <= {"é", "😀"}
    assert "".join(r["result"] for r in replies) == text
    assert replies[0]["page"]["total"] == len(text)
    r = page(ev(result=text), 1, 3)
    assert r["result"] == "😀é😀" and r["page"] == {
        "unit": "chars",
        "offset": 1,
        "next": 4,
        "total": len(text),
    }


def test_large_dict_pages_as_chars():
    big = {f"k{i}": "v" * 50 for i in range(2000)}
    replies = walk(ev(result=big))
    assert len(replies) > 1 and all(r["page"]["unit"] == "chars" for r in replies)
    text = "".join(r["result"] for r in replies)
    assert json.loads(text) == big and "\n " in text  # json.dumps(indent=1)
    assert len(replies[0]["result"].encode()) <= PAGE_BYTES


def test_too_big_item_becomes_a_marker():
    items = [{"a": 1}, {"blob": "x" * (PAGE_BYTES + 100)}, {"b": 2}]
    r = page(ev(result=items))
    assert r["result"][0] == {"a": 1} and r["result"][2] == {"b": 2}
    assert r["result"][1]["_too_big"] == 1 and r["result"][1]["bytes"] > PAGE_BYTES
    assert r["page"] == {"unit": "items", "offset": 0, "next": None, "total": 3}


def test_bad_offsets_fail():
    with pytest.raises(Fail) as e:
        page(ev(), -1)
    assert e.value.code == "bad_input"
    with pytest.raises(Fail):
        page(ev(), 0, -1)
    with pytest.raises(Fail):
        page(ev(), 0, 0)


def test_pages_are_stable_after_reload(tmp_path: Path):
    """The same id gives the same page from a fresh process, which the CLI relies on."""
    path = tmp_path / "ledger.jsonl"
    big = ev(result={f"k{i}": list(range(20)) for i in range(2000)})
    eid = Ledger(str(path)).record(big)
    first = page(big, 0)
    again = page(Ledger(str(path)).get(eid), 0)
    assert again == first
    assert page(Ledger(str(path)).get(eid), first["page"]["next"]) == page(
        big, first["page"]["next"]
    )
