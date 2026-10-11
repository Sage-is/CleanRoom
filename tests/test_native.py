"""Builtin native engine: detection, slices, inventories, show views and the xref index."""

from __future__ import annotations

import os
import platform
import struct
import sys
from pathlib import Path

import pytest

from cleanroom import engines
from cleanroom.evidence import Finding
from cleanroom.kinds import native
from cleanroom.target import Fail, open_target, read_head

HOST = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x86_64", "amd64": "x86_64"}
LONG_LITERAL = "REA_LONG_LITERAL_" + "x" * 4096 + "needle"


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLEANROOM_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("CLEANROOM_LEDGER", str(tmp_path / "ledger.jsonl"))
    monkeypatch.delenv("CLEANROOM_ENGINE", raising=False)


@pytest.fixture(scope="module")
def handle(c_fixture: Path) -> native.Handle:
    return native.open(open_target(str(c_fixture)))


def sym(h: native.Handle, name: str) -> str:
    """Mach-O prefixes C symbols with an underscore; ELF does not."""
    return name if h.fmt == "elf" else "_" + name


def names(items) -> list[str]:
    return [i["name"] for i in items]


def by_name(h: native.Handle, name: str) -> dict:
    return next(f for f in native.list(h, "functions") if f["name"] == sym(h, name))


def fail(code: str, fn, *args, **kwargs) -> Fail:
    with pytest.raises(Fail) as exc:
        fn(*args, **kwargs)
    assert exc.value.code == code, str(exc.value)
    return exc.value


# --- detect ---------------------------------------------------------------------------


def test_detect_fixture_and_ls(c_fixture: Path) -> None:
    assert native.detect(str(c_fixture), read_head(str(c_fixture)))
    if sys.platform == "darwin":
        assert native.detect("/bin/ls", read_head("/bin/ls"))


def test_detect_rejects_java_class_and_junk(tmp_path: Path) -> None:
    java = b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 45) + b"\0" * 32
    assert not native.detect("x.class", java)
    assert not native.detect("x.bin", bytes(range(256)))
    assert not native.detect("x.exe", b"MZ" + b"\0" * 100)
    assert not native.detect("x.exe", b"MZ")


def test_detect_pe_by_header_offset(tmp_path: Path) -> None:
    head = bytearray(b"MZ" + b"\0" * 0x3E)
    head[0x3C:0x40] = struct.pack("<I", 0x80)
    head += b"\0" * (0x80 - len(head)) + b"PE\0\0" + b"\0" * 20
    assert native.detect("x.exe", bytes(head))
    far = bytearray(head)
    far[0x3C:0x40] = struct.pack("<I", 0x2000)
    p = tmp_path / "far.exe"
    p.write_bytes(bytes(far[:0x40]) + b"\0" * (0x2000 - 0x40) + b"PE\0\0")
    assert native.detect(str(p), read_head(str(p)))


def test_elf_magic_detects() -> None:
    assert native.detect("x", b"\x7fELF" + b"\0" * 60)


# --- open, engines and slices ---------------------------------------------------------


def test_open_default_arch_is_the_host(handle: native.Handle) -> None:
    host = HOST.get(platform.machine(), platform.machine())
    assert handle.arch in (host, host + "e")
    assert native.info(handle)["arch"] == handle.arch


def test_info_shape(handle: native.Handle, c_fixture: Path) -> None:
    info = native.info(handle)
    assert set(info) >= {
        "format",
        "fat",
        "slices",
        "arch",
        "engine",
        "entry",
        "image_base",
        "sha256",
    }
    assert info["engine"].startswith("builtin (lief ")
    assert "capstone" in info["engine"]
    assert info["entry"].startswith("0x") and info["image_base"].startswith("0x")
    assert info["sha256"] == open_target(str(c_fixture)).sha256
    assert info["format"] in ("macho", "elf")


def test_open_each_fat_slice(c_fixture: Path) -> None:
    t = open_target(str(c_fixture))
    if not native.info(native.open(t))["fat"]:
        pytest.skip("fixture is a thin build")
    for arch in ("x86_64", "arm64"):
        h = native.open(t, arch=arch)
        assert h.arch == arch
        assert sym(h, "rea_leaf") in names(native.list(h, "functions"))
        assert native.show(h, "rea_leaf", "asm")
    err = fail("bad_input", native.open, t, arch="ppc")
    assert "x86_64" in (err.hint or "") and "arm64" in (err.hint or "")


def test_thin_binary_rejects_a_foreign_arch(handle: native.Handle, c_fixture: Path) -> None:
    if handle.fat:
        pytest.skip("FAT fixture: foreign arch is a missing-slice case")
    fail("bad_input", native.open, open_target(str(c_fixture)), arch="ppc")


def test_unknown_engine_is_bad_input(c_fixture: Path) -> None:
    fail("bad_input", native.open, open_target(str(c_fixture)), engine="decompile-o-matic")


def test_ghidra_without_install_dir_is_engine_missing(
    c_fixture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    err = fail("engine_missing", native.open, open_target(str(c_fixture)), engine="ghidra")
    assert "GHIDRA_INSTALL_DIR" in (err.hint or "")


def test_env_engine_is_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLEANROOM_ENGINE", "bogus")
    fail("bad_input", native.choose_engine, None)
    monkeypatch.setenv("CLEANROOM_ENGINE", "builtin")
    assert native.choose_engine(None) == "builtin"


def test_present_but_undriven_engine_is_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engines, "probe", lambda name: "/Applications/Hopper.app")
    err = fail("unsupported", native.choose_engine, "hopper")
    assert "P3" in err.message
    assert "P1" in fail("unsupported", native.choose_engine, "ghidra").message


def test_ida_is_never_chosen_automatically(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engines, "probe", lambda name: "present")
    assert native.choose_engine(None) == "builtin"
    assert native.ENGINE_ORDER == ("ghidra", "hopper", "builtin")
    assert "ida" not in native.ENGINE_ORDER


# --- list -----------------------------------------------------------------------------


def test_list_functions_has_the_fixture_symbols(handle: native.Handle) -> None:
    funcs = native.list(handle, "functions")
    got = names(funcs)
    for name in ("rea_leaf", "rea_branch", "rea_entry", "rea_cycle_a", "rea_cycle_b"):
        assert sym(handle, name) in got
    addrs = [int(f["address"], 16) for f in funcs]
    assert addrs == sorted(addrs) and len(set(addrs)) == len(addrs)
    assert all(f["size"] > 0 and f["address"].startswith("0x") for f in funcs)
    assert int(native.info(handle)["entry"], 16) in addrs


def test_list_sections_imports_exports_symbols(handle: native.Handle) -> None:
    secs = native.list(handle, "sections")
    text = next(s for s in secs if s["name"].endswith("__text") or s["name"] == ".text")
    assert text["exec"] and text["size"] > 0 and text["address"].startswith("0x")
    assert sym(handle, "puts") in names(native.list(handle, "imports"))
    assert sym(handle, "rea_leaf") in names(native.list(handle, "exports"))
    syms = native.list(handle, "symbols")
    leaf = next(s for s in syms if s["name"] == sym(handle, "rea_leaf"))
    assert leaf["type"] == "func"
    assert len({(s["name"], s["address"]) for s in syms}) == len(syms)


def test_list_strings(handle: native.Handle) -> None:
    items = native.list(handle, "strings")
    values = [s.get("value") for s in items]
    assert "REA_C_LEAF" in values
    assert "REA_UTF8_é_😀" in values
    assert LONG_LITERAL in values
    latin = [s for s in items if s.get("bytes") == b"REA_LATIN1_\xff".hex()]
    assert latin and "value" not in latin[0]
    assert all(s["address"].startswith("0x") and s["section"] for s in items)


def test_list_rejects_unknown_what(handle: native.Handle) -> None:
    fail("bad_input", native.list, handle, "threads")


def test_match_substring_is_case_insensitive(handle: native.Handle) -> None:
    got = names(native.list(handle, "functions", match="REA_LEAF"))
    assert got == [sym(handle, "rea_leaf")]
    assert native.list(handle, "strings", match="needle")[0]["value"] == LONG_LITERAL


def test_match_regex_form(handle: native.Handle) -> None:
    got = names(native.list(handle, "functions", match="/cycle_[ab]$/"))
    assert sorted(got) == sorted(sym(handle, n) for n in ("rea_cycle_a", "rea_cycle_b"))
    fail("bad_input", native.list, handle, "functions", match="/(/")


def test_pathological_regex_is_killed_not_run(
    handle: native.Handle, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(native, "MATCH_BUDGET", 1.0)
    items = [{"name": "a" * 40 + "!"}]
    got = native._match(items, "/(a+)+$/")
    assert isinstance(got, Finding) and got.value == []
    assert "killed after 1 s" in got.unknowns[0]
    assert native._match(items, "/^a+!$/") == items


def test_match_budget_reports_an_unknown(
    handle: native.Handle, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(native, "MATCH_BUDGET", 0.0)
    got = native.list(handle, "functions", match="rea")
    assert isinstance(got, Finding)
    assert got.confidence == "observed" and "match stopped" in got.unknowns[0]
    assert len(got.value) <= 1


# --- show -----------------------------------------------------------------------------


def test_show_asm_lists_one_instruction_per_line(handle: native.Handle) -> None:
    text = native.show(handle, "rea_leaf", "asm")
    lines = text.splitlines()
    assert lines and all(ln.startswith("0x") and ": " in ln for ln in lines)
    assert int(lines[0].split(":")[0], 16) == int(by_name(handle, "rea_leaf")["address"], 16)


def test_show_pseudo_is_unsupported(handle: native.Handle) -> None:
    err = fail("unsupported", native.show, handle, "rea_leaf", "pseudo")
    assert "Ghidra" in (err.hint or "")


def test_show_info_auto_and_bytes(handle: native.Handle) -> None:
    info = native.show(handle, "rea_leaf", "info")
    assert info["name"] == sym(handle, "rea_leaf") and info["callers"] == 1
    assert info["callees"] == 1 and info["size"] > 0 and info["section"]
    auto = native.show(handle, "rea_leaf")
    assert auto["asm"].splitlines() == native.show(handle, "rea_leaf", "asm").splitlines()[:40]
    raw = native.show(handle, "rea_leaf", "bytes")
    assert raw["complete"] and len(raw["hex"]) == 2 * raw["size"]
    assert raw["address"] == info["address"]
    big = native.show(handle, "rea_long_literal_procedure", "bytes")
    assert len(big["hex"]) <= 512
    fail("bad_input", native.show, handle, "rea_leaf", "hex")


def test_address_ref_resolves_to_the_containing_function(handle: native.Handle) -> None:
    leaf = by_name(handle, "rea_leaf")
    start = int(leaf["address"], 16)
    assert native.show(handle, leaf["address"], "info")["name"] == leaf["name"]
    assert native.show(handle, f"0x{start + 4:x}", "info")["name"] == leaf["name"]
    assert native.show(handle, f"ram:0x{start:x}", "info")["name"] == leaf["name"]
    assert native.show(handle, f"{start:x}", "info")["name"] == leaf["name"]


def test_name_lookup_tries_exact_then_underscore_then_suffix(handle: native.Handle) -> None:
    leaf = sym(handle, "rea_leaf")
    assert native.show(handle, leaf, "info")["name"] == leaf
    assert native.show(handle, "rea_leaf", "info")["name"] == leaf
    assert native.show(handle, "a_leaf", "info")["name"] == leaf


def test_ambiguous_suffix_lists_candidates(handle: native.Handle) -> None:
    err = fail("ambiguous", native.show, handle, "cycle_", "info")
    assert sym(handle, "rea_cycle_a") in (err.hint or "")
    assert sym(handle, "rea_cycle_b") in (err.hint or "")


def test_unknown_refs_are_not_found(handle: native.Handle) -> None:
    fail("not_found", native.show, handle, "no_such_function", "info")
    fail("not_found", native.show, handle, "0x10", "info")
    fail("bad_input", native.show, handle, "0xzz", "info")
    fail("bad_input", native.show, handle, "  ", "info")


def test_short_refs_do_not_resolve_to_arbitrary_functions(handle: native.Handle) -> None:
    for ref in ("e", "a", "_a"):
        err = fail("not_found", native.show, handle, ref, "info")
        assert "list functions" in (err.hint or "")
    err = fail("not_found", native.show, handle, "add", "info")
    assert err.message == "no function named 'add', and 0xadd is not inside a known function"


def test_bare_hex_wins_over_a_substring(handle: native.Handle) -> None:
    """Bare hex is tried right after the exact names, before any fuzzy match."""
    leaf = by_name(handle, "rea_leaf")
    assert native.show(handle, leaf["address"][2:], "info")["name"] == leaf["name"]
    funcs = native.list(handle, "functions")
    funcs.append({"name": "f_" + leaf["address"][2:], "address": "0x0", "size": 1})
    assert native.show(handle, leaf["address"][2:], "info")["name"] == leaf["name"]


def test_views_advertised_match_the_engine(handle: native.Handle) -> None:
    assert native.info(handle)["views"] == ["auto", "info", "asm", "bytes"]


def test_section_offsets_are_file_offsets(handle: native.Handle, c_fixture: Path) -> None:
    data = c_fixture.read_bytes()
    for sec in handle.sections:
        head = bytes(sec["_obj"].content[:16])
        if head:
            assert data[sec["offset"] : sec["offset"] + len(head)] == head, sec["name"]


def test_long_function_disassembly_is_capped(
    handle: native.Handle, monkeypatch: pytest.MonkeyPatch
) -> None:
    big = by_name(handle, "rea_long_literal_procedure")
    monkeypatch.setattr(native, "DISASM_MAX", 16)
    got = native.show(handle, "rea_long_literal_procedure", "asm")
    assert isinstance(got, Finding) and got.unknowns[0].startswith("disassembly stops at 16")
    assert len(got.value.splitlines()) <= 16
    monkeypatch.setattr(native, "DISASM_CHUNK", 2)
    monkeypatch.setattr(native, "DISASM_MAX", big["size"])
    whole = native.show(handle, "rea_long_literal_procedure", "asm")
    assert isinstance(whole, str) and len(whole.splitlines()) > 4


# --- xrefs ----------------------------------------------------------------------------


def test_xrefs_to_leaf_come_from_branch(handle: native.Handle) -> None:
    items = native.xrefs(handle, "rea_leaf", "to")
    items = items.value if isinstance(items, Finding) else items
    assert items and {i["name"] for i in items} == {sym(handle, "rea_branch")}
    assert {i["type"] for i in items} == {"call"}
    branch = by_name(handle, "rea_branch")
    assert all(i["ref"] == branch["address"] for i in items)
    assert all(i["at"].startswith("0x") and "direction" not in i for i in items)


def test_xrefs_from_branch_call_leaf(handle: native.Handle) -> None:
    items = native.xrefs(handle, "rea_branch", "from")
    items = items.value if isinstance(items, Finding) else items
    leaf = by_name(handle, "rea_leaf")
    calls = [i for i in items if i["type"] == "call"]
    assert calls and all(i["ref"] == leaf["address"] and i["name"] == leaf["name"] for i in calls)


def test_xrefs_both_marks_direction_and_sees_strings_and_imports(handle: native.Handle) -> None:
    items = native.xrefs(handle, "rea_leaf", "both")
    items = items.value if isinstance(items, Finding) else items
    assert {i["direction"] for i in items} == {"to", "from"}
    out = [i for i in items if i["direction"] == "from"]
    assert {i["type"] for i in out} >= {"import", "string"}
    assert sym(handle, "puts") in {i["name"] for i in out if i["type"] == "import"}
    strings = {s["address"]: s for s in native.list(handle, "strings")}
    leaf_strings = [strings[i["ref"]]["value"] for i in out if i["type"] == "string"]
    assert leaf_strings == ["REA_C_LEAF"]
    fail("bad_input", native.xrefs, handle, "rea_leaf", "sideways")


def test_xrefs_to_a_string_address_names_its_users(handle: native.Handle) -> None:
    needle = next(s for s in native.list(handle, "strings") if s.get("value") == LONG_LITERAL)
    items = native.xrefs(handle, needle["address"], "to")
    items = items.value if isinstance(items, Finding) else items
    assert names(items) == [sym(handle, "rea_long_literal_procedure")]
    assert items[0]["type"] == "string"
    fail("not_found", native.xrefs, handle, "0x10", "to")


def test_xrefs_to_an_import_by_name_and_bare_hex(handle: native.Handle) -> None:
    for ref in ("puts", "_puts"):
        items = native.xrefs(handle, ref, "to")
        items = items.value if isinstance(items, Finding) else items
        assert items and {i["type"] for i in items} == {"import"}
        assert sym(handle, "rea_leaf") in names(items)
    fail("not_found", native.xrefs, handle, "no_such_import", "to")
    needle = next(s for s in native.list(handle, "strings") if s.get("value") == LONG_LITERAL)
    bare = native.xrefs(handle, needle["address"][2:], "to")
    bare = bare.value if isinstance(bare, Finding) else bare
    assert names(bare) == [sym(handle, "rea_long_literal_procedure")]


def test_cycle_functions_reference_each_other(handle: native.Handle) -> None:
    a, b = by_name(handle, "rea_cycle_a"), by_name(handle, "rea_cycle_b")
    out = native.xrefs(handle, "rea_cycle_a", "from")
    out = out.value if isinstance(out, Finding) else out
    assert [i["ref"] for i in out if i["type"] == "call"] == [b["address"]]
    back = native.xrefs(handle, "rea_cycle_b", "to")
    back = back.value if isinstance(back, Finding) else back
    assert {i["ref"] for i in back} == {a["address"]}


def test_close_is_a_no_op(handle: native.Handle) -> None:
    assert native.close(handle) is None
    assert sym(handle, "rea_leaf") in names(native.list(handle, "functions"))


# --- module contract ------------------------------------------------------------------


def test_module_constants() -> None:
    assert native.LIST_WHAT == (
        "functions",
        "symbols",
        "strings",
        "sections",
        "imports",
        "exports",
    )
    assert set(native.SHOW_VIEWS) == {"auto", "info", "asm", "bytes", "pseudo"}
    assert set(native.DIFF_KEYS) == set(native.LIST_WHAT)
    assert native.DIFF_IGNORE == {"address", "offset", "size"}
    for fn in ("detect", "open", "info", "list", "show", "xrefs", "close"):
        assert callable(getattr(native, fn))


# --- /bin/ls --------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "darwin", reason="/bin/ls is FAT only on macOS")
def test_bin_ls_is_fat_with_imports_and_an_entry() -> None:
    h = native.open(open_target("/bin/ls"))
    info = native.info(h)
    assert info["fat"] is True and len(info["slices"]) == 2
    imports = names(native.list(h, "imports"))
    assert "_malloc" in imports or "_free" in imports
    assert native.show(h, info["entry"], "asm").count("\n") > 10
    out = native.xrefs(h, info["entry"], "from")
    out = out.value if isinstance(out, Finding) else out
    assert any(i["type"] == "import" and i["name"].startswith("_") for i in out)
    assert any(i["type"] == "call" for i in out)
    assert os.environ["CLEANROOM_CACHE"].endswith("cache")
