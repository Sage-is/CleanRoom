"""target.py: identity, detection over KIND_ORDER, open_target, parse_ref and the FAT hint."""

from __future__ import annotations

import hashlib
import os
import struct
import sys
import types
from pathlib import Path

import pytest

from cleanroom import target
from cleanroom.target import Fail, Target, is_fat_macho, open_target, parse_ref

FAT = b"\xca\xfe\xba\xbe"
FAT64 = b"\xca\xfe\xba\xbf"


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLEANROOM_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("CLEANROOM_LEDGER", str(tmp_path / "ledger.jsonl"))


@pytest.fixture
def fake_kind(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    """A kind module injected as ``cleanroom.kinds.fake``; KIND_ORDER also names a kind
    that does not exist, so detect() must skip it."""
    module = types.ModuleType("cleanroom.kinds.fake")
    module.detect = lambda path, head: head.startswith(b"FAKE") or os.path.isdir(path)
    monkeypatch.setitem(sys.modules, "cleanroom.kinds.fake", module)
    monkeypatch.setattr(target, "KIND_ORDER", ("no_such_kind", "fake"))
    return module


def _blob(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


# --- digests -----------------------------------------------------------------


def test_sha256_file_matches_hashlib(tmp_path: Path) -> None:
    data = os.urandom(3 * 1024 * 1024 + 17)  # crosses the 1 MiB chunk boundary
    p = _blob(tmp_path, "blob", data)
    assert target.sha256_file(str(p)) == hashlib.sha256(data).hexdigest()


def test_sha256_file_refuses_a_file_that_changes_under_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = _blob(tmp_path, "moving", b"before")
    real_stat, calls = os.stat, []

    def stat_then_mutate(path, *args, **kwargs):
        calls.append(path)
        if len(calls) == 2:  # the "after" stat sees a different size and mtime
            p.write_bytes(b"after, longer")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(target.os, "stat", stat_then_mutate)
    with pytest.raises(Fail) as exc:
        target.sha256_file(str(p))
    assert exc.value.code == "failed"


def test_read_head_is_bounded(tmp_path: Path) -> None:
    p = _blob(tmp_path, "big", b"x" * 10_000)
    assert len(target.read_head(str(p))) == target.HEAD_BYTES == 4096
    assert target.read_head(str(p), 3) == b"xxx"


def test_cache_dir_honours_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLEANROOM_CACHE", str(tmp_path / "deep" / "cache"))
    assert target.cache_dir() == tmp_path / "deep" / "cache"
    assert (tmp_path / "deep" / "cache").is_dir()


# --- FAT hint ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("head", "expected"),
    [
        (FAT + struct.pack(">I", 2), True),
        (FAT64 + struct.pack(">I", 1), True),
        (FAT + struct.pack(">I", 30), True),
        (FAT + struct.pack(">I", 31), False),
        (FAT + struct.pack(">I", 0), False),
        (FAT + b"\x00\x00\x00\x34", False),  # Java class: minor 0, major 52
        (FAT + b"\x00\x00\x00\x41" + b"junk", False),  # Java 21 class
        (FAT, False),  # too short to carry nfat_arch
        (b"\xfe\xed\xfa\xcf" + struct.pack(">I", 2), False),  # thin 64-bit Mach-O
        (b"", False),
    ],
)
def test_is_fat_macho(head: bytes, expected: bool) -> None:
    assert is_fat_macho(head) is expected


# --- detect ----------------------------------------------------------------------


def test_detect_skips_missing_kinds_and_finds_the_fake(tmp_path: Path, fake_kind) -> None:
    assert target.detect("x", b"FAKE file") == "fake"
    assert target.detect("x", b"other") is None


def test_detect_returns_the_first_kind_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, answer in (("alpha", True), ("beta", True)):
        module = types.ModuleType(f"cleanroom.kinds.{name}")
        module.detect = lambda path, head, answer=answer: answer
        monkeypatch.setitem(sys.modules, f"cleanroom.kinds.{name}", module)
    monkeypatch.setattr(target, "KIND_ORDER", ("alpha", "beta"))
    assert target.detect("x", b"") == "alpha"
    monkeypatch.setattr(target, "KIND_ORDER", ("beta", "alpha"))
    assert target.detect("x", b"") == "beta"


def test_detect_ignores_a_kind_without_detect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        sys.modules, "cleanroom.kinds.bare", types.ModuleType("cleanroom.kinds.bare")
    )
    monkeypatch.setattr(target, "KIND_ORDER", ("bare",))
    assert target.detect("x", b"anything") is None


@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a native /bin/ls")
def test_ls_and_the_fixture_are_native(c_fixture: Path) -> None:
    pytest.importorskip("cleanroom.kinds.native")
    for path in ("/bin/ls", str(c_fixture)):
        assert target.detect(path, target.read_head(path)) == "native"
        assert open_target(path).kind == "native"


# --- open_target -------------------------------------------------------------------


def test_open_target_binds_a_detected_file(tmp_path: Path, fake_kind) -> None:
    data = b"FAKE" + os.urandom(100)
    p = _blob(tmp_path, "thing.bin", data)
    t = open_target(str(p))
    assert t == Target(str(p), hashlib.sha256(data).hexdigest(), len(data), "fake")
    assert isinstance(t, Target)


def test_open_target_makes_the_path_absolute(tmp_path: Path, fake_kind, monkeypatch) -> None:
    _blob(tmp_path, "rel.bin", b"FAKE")
    monkeypatch.chdir(tmp_path)
    assert open_target("rel.bin").path == str(tmp_path / "rel.bin")


def test_open_target_missing_path_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(Fail) as exc:
        open_target(str(tmp_path / "nope"))
    assert exc.value.code == "not_found"


def test_open_target_unknown_blob_is_unsupported(tmp_path: Path, fake_kind) -> None:
    p = _blob(tmp_path, "mystery", bytes(range(256)))
    with pytest.raises(Fail) as exc:
        open_target(str(p))
    assert exc.value.code == "unsupported"
    assert "kind=" in (exc.value.hint or "")


def test_open_target_explicit_kind_skips_detection(tmp_path: Path, fake_kind) -> None:
    p = _blob(tmp_path, "forced", b"not fake at all")
    assert open_target(str(p), kind="fake").kind == "fake"
    with pytest.raises(Fail) as exc:
        open_target(str(p), kind="no_such_kind")
    assert exc.value.code == "unsupported"
    assert exc.value.hint == "installed: fake"  # the hint names what can be passed
    with pytest.raises(Fail) as exc:
        open_target(str(p))
    assert exc.value.hint.startswith("pass kind= (fake)")
    with pytest.raises(Fail):
        open_target(str(p), kind="../bad")


def test_open_target_takes_the_path_as_given(tmp_path: Path, fake_kind, monkeypatch) -> None:
    _blob(tmp_path, "~nobody", b"FAKE")
    monkeypatch.chdir(tmp_path)
    assert open_target("~nobody").path == str(tmp_path / "~nobody")


def test_open_target_http_url_is_web() -> None:
    for url in ("http://example.test/app", "https://example.test/app?x=1"):
        t = open_target(url)
        assert t == Target(url, hashlib.sha256(url.encode()).hexdigest(), 0, "web")
    assert open_target("https://example.test", kind="web").kind == "web"
    with pytest.raises(Fail) as exc:
        open_target("https://example.test", kind="native")
    assert exc.value.code == "bad_input"


def test_open_target_directory_identity_tracks_its_listing(tmp_path: Path, fake_kind) -> None:
    app = tmp_path / "app"
    (app / "sub").mkdir(parents=True)
    (app / "package.json").write_bytes(b"{}")
    (app / "sub" / "main.js").write_bytes(b"x" * 10)
    first = open_target(str(app))
    assert first.kind == "fake" and first.size == 12
    assert open_target(str(app)).sha256 == first.sha256
    (app / "sub" / "extra.js").write_bytes(b"y")
    second = open_target(str(app))
    assert second.sha256 != first.sha256 and second.size == 13


# --- parse_ref ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("add", ("name", "add")),
        ("face", ("name", "face")),
        ("_rea_leaf", ("name", "_rea_leaf")),
        ("-[Foo bar:]", ("name", "-[Foo bar:]")),
        ("ns::func", ("name", "ns::func")),
        ("0xadd", ("addr", 0xADD, None)),
        ("0XADD", ("addr", 0xADD, None)),
        ("ram:0x10", ("addr", 0x10, "ram")),
        ("  0x100003f20 ", ("addr", 0x100003F20, None)),
        ("ram%3A0:0x0", ("addr", 0, "ram%3A0")),
    ],
)
def test_parse_ref(ref: str, expected: tuple) -> None:
    assert parse_ref(ref) == expected


@pytest.mark.parametrize("ref", ["0x", "0xzz", "ram:0x1g"])
def test_parse_ref_rejects_a_bad_address(ref: str) -> None:
    with pytest.raises(Fail) as exc:
        parse_ref(ref)
    assert exc.value.code == "bad_input"


def test_fail_round_trip() -> None:
    f = Fail("timeout", "slow", "raise --timeout")
    assert f.to_dict() == {"code": "timeout", "message": "slow", "hint": "raise --timeout"}
    assert Fail("failed", "x").to_dict() == {"code": "failed", "message": "x"}
    with pytest.raises(ValueError):
        Fail("nope", "x")
