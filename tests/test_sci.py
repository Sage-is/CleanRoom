"""Sierra SCI kind: detection, decompression, script parsing, the bytecode walker and verbs.

Every test but the last runs on the synthetic game in ``tests/fixtures/sci.py``. The last
reads a real game when ``CLEANROOM_SCI_GAME`` names its directory; Sierra data is never
committed.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import cleanroom.graph  # noqa: F401 - registers trace and diff
from cleanroom.evidence import Finding, Ledger
from cleanroom.kinds import sci
from cleanroom.target import Fail, detect, open_target
from cleanroom.tools import REGISTRY, Session, invoke
from tests.fixtures import sci as fx

GAME = os.environ.get("CLEANROOM_SCI_GAME")


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLEANROOM_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("CLEANROOM_LEDGER", str(tmp_path / "ledger.jsonl"))


@pytest.fixture(scope="module")
def game(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return fx.build(tmp_path_factory.mktemp("sci") / "game")


@pytest.fixture(scope="module")
def handle(game: Path) -> sci.Handle:
    return sci.open(open_target(str(game)))


def fail(code: str, fn, *args, **kwargs) -> Fail:
    with pytest.raises(Fail) as exc:
        fn(*args, **kwargs)
    assert exc.value.code == code, str(exc.value)
    return exc.value


def names(items) -> list[str]:
    return [i["name"] for i in (items.value if isinstance(items, Finding) else items)]


# --- detect and open --------------------------------------------------------------------


def test_detect_directory_and_map_file(game: Path, tmp_path: Path) -> None:
    assert sci.detect(str(game), b"")
    assert sci.detect(str(game / "resource.map"), b"")
    assert detect(str(game), b"") == "sci"
    assert not sci.detect(str(tmp_path), b"")
    junk = tmp_path / "junk"
    junk.mkdir()
    (junk / "resource.map").write_bytes(b"not a map at all")
    assert not sci.detect(str(junk), b"")
    assert not sci.detect(str(game / "resource.000"), b"")


def test_open_map_file_binds_its_directory(game: Path) -> None:
    h = sci.open(open_target(str(game / "resource.map")))
    assert h.root == str(game) and "proc_0_1" in names(sci.list(h, "functions"))


def test_info(handle: sci.Handle) -> None:
    info = sci.info(handle)
    assert info["engine"] == "builtin-sci" and info["arch"] == "sci-vm"
    assert info["format"] == "SCI0"  # nothing compressed: the generations look alike
    counts = [info[k] for k in ("resources", "scripts", "duplicates", "patches")]
    assert counts == [4, 1, 0, 0]
    assert len(info["content_sha256"]) == 64


def test_engine_other_than_builtin_is_unsupported(game: Path) -> None:
    fail("unsupported", sci.open, open_target(str(game)), engine="ghidra")


def test_later_map_is_detected_but_unsupported(tmp_path: Path) -> None:
    root = tmp_path / "sci11"
    root.mkdir()
    (root / "resource.map").write_bytes(bytes([0x80, 0x10, 0, 0xFF, 0x20, 0]) + b"\0" * 32)
    assert sci.detect(str(root), b"")
    assert "type-table" in fail("unsupported", sci.open, open_target(str(root), "sci")).message


def test_duplicate_entries_keep_the_first(tmp_path: Path) -> None:
    h = sci.open(open_target(str(fx.build(tmp_path / "g", dupe=True))))
    assert sci.info(h)["duplicates"] == 1 and sci.info(h)["resources"] == 4


def test_content_digest_sees_a_same_size_edit(tmp_path: Path) -> None:
    root = fx.build(tmp_path / "g")
    before = sci.open(open_target(str(root))).content
    vol = bytearray((root / "resource.000").read_bytes())
    vol[-1] ^= 0xFF
    (root / "resource.000").write_bytes(bytes(vol))
    assert sci.open(open_target(str(root))).content != before


# --- decompression ----------------------------------------------------------------------


@pytest.mark.parametrize("version", ["SCI0", "SCI1-early"])
@pytest.mark.parametrize("method", [1, 2])
def test_compressed_games_decode_alike(
    tmp_path: Path, handle: sci.Handle, version: str, method: int
) -> None:
    h = sci.open(open_target(str(fx.build(tmp_path / "g", method, version))))
    assert h.version == version
    for key in fx.resources():
        assert sci.resource(h, *key) == sci.resource(handle, *key)


def test_decoders_round_trip_longer_data() -> None:
    data = bytes(range(256)) * 20 + b"\0" * 300
    assert sci._lzw(fx.lzw_literals(data), len(data)) == data
    assert sci._huffman(fx.huffman_literals(data), len(data)) == data
    assert sci._lzw1(fx.lzw1_literals(data), len(data)) == data


def test_lzw_back_references() -> None:
    # literals A, B, then code 0x102 (= "AB"), LSB first at 9 bits
    acc = 0x41 | 0x42 << 9 | 0x102 << 18 | 0x101 << 27
    assert sci._lzw(acc.to_bytes(5, "little"), 4) == b"ABAB"


def test_truncated_stream_fails(handle: sci.Handle) -> None:
    fail("failed", sci._lzw, b"\x41", 4)


def test_patch_file_overrides_the_map(tmp_path: Path) -> None:
    root = fx.build(tmp_path / "g")
    renamed = [("xpos" if s == "x" else s) for s in fx.SELECTORS]
    (root / "vocab.997").write_bytes(bytes([0x86, 0]) + fx.names_sci0(renamed))
    h = sci.open(open_target(str(root)))
    assert sci.info(h)["patches"] == 1
    assert sci.show(h, "thing")["properties"]["xpos"] == 3


def test_missing_resource(handle: sci.Handle) -> None:
    fail("not_found", sci.resource, handle, "view", 100)
    fail("not_found", sci.show, handle, "view:100")


# --- scripts and bytecode ---------------------------------------------------------------


def test_script_parse(handle: sci.Handle) -> None:
    s = sci.script(handle, 0)
    assert [o["name"] for o in s["objects"]] == ["Obj", "thing"]
    assert [b["type"] for b in s["blocks"]] == [7, 2, 6, 1, 5, 10]
    assert s["locals"] == [7, 8] and [t for _, t in s["strings"]] == fx.STRINGS
    obj, thing = s["objects"]
    assert obj["class"] and obj["super"] == 0xFFFF and obj["props"] == [0, 1, 2, 3, 6]
    assert s["exports"] == [thing["address"], 14]


def test_functions_cover_every_entry_kind(handle: sci.Handle) -> None:
    kinds = {f["name"]: f["kind"] for f in sci.list(handle, "functions")}
    assert kinds == {
        "proc_0_1": "procedure",
        "localproc_0_0020": "local",
        "Obj::init": "method",
        "thing::doit": "method",
        "localproc_0_0038": "unreferenced",
    }


def test_every_code_byte_is_decoded_once(handle: sci.Handle) -> None:
    insns, _ = sci._decoded(handle, 0)
    (start, end) = sci.script(handle, 0)["code"][0]
    assert sum(i[2] for i in insns.values()) == end - start


def test_disassembly_reassembles_to_the_same_bytes(handle: sci.Handle) -> None:
    data = sci.script(handle, 0)["data"]
    for off, (op, args, size) in sci._decoded(handle, 0)[0].items():
        small = data[off] & 1
        assert fx.asm([(op, args, small)]) == data[off : off + size]


def test_asm_annotations(handle: sci.Handle) -> None:
    proc = sci.show(handle, "proc_0_1", "asm")
    assert "lofsa 0x006f  ; thing" in proc and "send 4  ; Obj::init(0)" in proc
    assert "callk 1, 0  ; Animate" in proc and "call 0x0020, 0  ; localproc_0_0020" in proc
    assert "self 6  ; Obj::x(1)" in sci.show(handle, "Obj::init", "asm")
    doit = sci.show(handle, "thing::doit", "asm")
    assert "super 0, 4  ; Obj::init(0)" in doit and "'hello'" in doit and "pToa 8  ; x" in doit


def test_frames() -> None:
    assert sci._frames([4, 0, 6, 1, 9]) == [(4, 0), (6, 1)]
    assert sci._frames([4, 1]) is None
    assert sci._frames([4, None]) is None


# --- list, show, resolve ----------------------------------------------------------------


def test_lists(handle: sci.Handle) -> None:
    objs = {o["name"]: o for o in sci.list(handle, "objects")}
    assert objs["Obj"]["type"] == "class" and objs["thing"]["super"] == "Obj"
    assert names(sci.list(handle, "kernels")) == fx.KERNELS
    assert names(sci.list(handle, "selectors")) == fx.SELECTORS
    assert [s["value"] for s in sci.list(handle, "strings")] == fx.STRINGS
    assert [r["id"] for r in sci.list(handle, "resources")][0] == "script:0"
    assert sci.list(handle, "scripts")[0]["objects"] == 2
    assert names(sci.list(handle, "functions", "doit")) == ["thing::doit"]
    assert names(sci.list(handle, "functions", "/^local/")) == [
        "localproc_0_0020",
        "localproc_0_0038",
    ]
    fail("bad_input", sci.list, handle, "symbols")


def test_resolve_forms(handle: sci.Handle) -> None:
    assert sci._resolve(handle, "0x24")[1]["name"] == "Obj::init"  # inside it
    assert sci._resolve(handle, "0:0x23")[1]["name"] == "Obj::init"
    assert sci._resolve(handle, "0x6f") == ("object", sci._resolve(handle, "thing")[1])
    assert sci._resolve(handle, "doit")[1]["name"] == "thing::doit"
    assert sci._resolve(handle, "script:0") == ("resource", (2, 0))
    assert sci._resolve(handle, "kernel:Animate") == ("kernel", "Animate")
    fail("ambiguous", sci._resolve, handle, "localproc")
    fail("not_found", sci._resolve, handle, "nothing_here")
    fail("not_found", sci._resolve, handle, "1:0x0")
    fail("not_found", sci._resolve, handle, "kernel:Nope")
    fail("bad_input", sci._resolve, handle, "x:0x10")
    fail("bad_input", sci._resolve, handle, " ")


def test_show_function_views(handle: sci.Handle) -> None:
    auto = sci.show(handle, "proc_0_1")
    assert auto["address"] == "0xe" and auto["kind"] == "procedure" and "asm" in auto
    assert auto["callees"] == 3 and auto["callers"] == 0
    assert sci.show(handle, "Obj::init", "info")["callers"] == 2
    assert sci.show(handle, "proc_0_1", "hex")["hex"].startswith("3904")
    assert sci.show(handle, "thing::doit", "object")["name"] == "thing"
    fail("bad_input", sci.show, handle, "proc_0_1", "object")
    fail("bad_input", sci.show, handle, "proc_0_1", "pseudo")


def test_show_object_resource_and_names(handle: sci.Handle) -> None:
    thing = sci.show(handle, "thing")
    assert thing["properties"] == {"species": 0, "superClass": 0, "-info-": 0, "name": 137, "x": 3}
    assert thing["methods"] == {"doit": "0x2b"} and thing["super"] == "Obj"
    fail("bad_input", sci.show, handle, "thing", "asm")
    script = sci.show(handle, "script:0")
    assert script["size"] == len(sci.resource(handle, "script", 0)) and script["blocks"]
    vocab = sci.show(handle, "vocab:997", "hex")
    assert vocab["complete"] and bytes.fromhex(vocab["hex"]) == fx.names_sci0(fx.SELECTORS)
    fail("bad_input", sci.show, handle, "vocab:997", "asm")
    assert sci.show(handle, "kernel:Animate") == {
        "name": "Animate",
        "ref": "kernel:Animate",
        "number": 1,
        "users": 1,
    }
    assert sci.show(handle, "selector:new")["users"] == 0


def test_xrefs(handle: sci.Handle) -> None:
    to_init = sci.xrefs(handle, "Obj::init", "to")
    assert sorted(names(to_init)) == ["proc_0_1", "thing::doit"]
    assert names(sci.xrefs(handle, "kernel:Animate", "to")) == ["proc_0_1"]
    assert [i["type"] for i in sci.xrefs(handle, "thing", "to")] == ["data"]
    both = sci.xrefs(handle, "Obj::init")
    assert {i["direction"] for i in both} == {"to", "from"}
    assert sci.xrefs(handle, "Obj::init", "from")[0]["type"] == "data"  # self x: a property
    fail("bad_input", sci.xrefs, handle, "Obj::init", "sideways")
    fail("unsupported", sci.xrefs, handle, "script:0")


def test_unresolved_send_names_its_selector(tmp_path: Path, monkeypatch) -> None:
    # Replace "lofsa thing" in proc with "lag 0": the receiver is now unknown.
    root = fx.build(tmp_path / "g")
    program = [("lag", [0], 0) if i == ("lofsa", ["@thing"], 0) else i for i in fx.PROGRAM]
    monkeypatch.setattr(fx, "PROGRAM", program)
    fx.build(root)
    h = sci.open(open_target(str(root)))
    got = sci.xrefs(h, "proc_0_1", "from")
    assert isinstance(got, Finding) and sci.UNRESOLVED in got.unknowns
    assert {"ref": "selector:init", "name": "init", "type": "call", "at": "0x14"} in got.value


# --- through the session: open, trace, diff ---------------------------------------------


def run(session: Session, verb: str, **args) -> dict:
    return invoke(session, REGISTRY[verb], args)


def test_session_open_trace_and_diff(game: Path, tmp_path: Path) -> None:
    session = Session(Ledger(str(tmp_path / "ledger.jsonl")))
    opened = run(session, "open", path=str(game))["result"]
    assert opened["kind"] == "sci" and "functions" in opened["list"]
    trace = run(session, "trace", start="proc_0_1", goal="Obj::init")["result"]
    assert trace["found"] and len(trace["path"]) == 2
    other = tmp_path / "other"
    program = [i for i in fx.PROGRAM if i != "orphan" and i != ("ldi", [1], 1)]
    program = program[:-1]  # drop the orphan's ret too
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(fx, "PROGRAM", program)
        fx.build(other)
    reply = run(session, "diff", a=str(game), b=str(other), what="functions")
    assert reply["result"]["categories"]["functions"]["removed"] == ["localproc_0_0038"]


def test_open_reply_through_the_cli_shape(game: Path, tmp_path: Path) -> None:
    session = Session(Ledger(str(tmp_path / "ledger.jsonl")))
    reply = run(session, "open", path=str(game))
    assert reply["engine"] == "builtin-sci" and reply["result"]["format"] == "SCI0"


# --- a real game, when one is named -----------------------------------------------------


@pytest.mark.skipif(not GAME, reason="set CLEANROOM_SCI_GAME to a game directory")
def test_real_game() -> None:
    h = sci.open(open_target(GAME))
    kernels, selectors = len(sci._vocab(h, 999)), len(sci._vocab(h, 997))
    for (typ, num), _ in sorted(h.where.items()):
        sci.resource(h, typ, num)  # raises unless it decodes to its declared size
    for num in sci._scripts(h):
        s, (insns, _) = sci.script(h, num), sci._decoded(h, num)
        data = s["data"]
        covered = set()
        for off, (op, args, size) in insns.items():
            assert fx.asm([(op, args, data[off] & 1)]) == data[off : off + size], (num, off)
            covered.update(range(off, off + size))
        for start, end in s["code"]:  # what no instruction covers is zero padding
            assert not any(data[i] for i in range(start, end) if i not in covered), num
    assert selectors > 0
    for f in sci.list(h, "functions"):
        lines, edges = sci._flow(h, f["script"], f["offset"])
        assert lines
        assert not any(e["name"].startswith("sel_") for e in edges), f["name"]
    # A short vocab.999 is the only unknown a sound game leaves.
    assert all("vocab.999" in u for u in h.unknowns), h.unknowns
    assert all(int(u.split()[1]) >= kernels for u in h.unknowns)
