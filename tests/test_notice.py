"""NOTICE lists every file adapted from rea and every verbatim fixture folder."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTICE = ROOT / "NOTICE"
ADAPTED = "Adapted files:"
FIXTURES = "Verbatim fixtures:"
NONE = "  (none yet)"
ENTRY = re.compile(r"^  (\S+)  from (\S+)$")
MARKER = "Adapted from rea"
SCAN_DIRS = ("cleanroom", "tests")


def _lines() -> list[str]:
    assert NOTICE.is_file(), f"{NOTICE} is missing"
    return NOTICE.read_text(encoding="utf-8").splitlines()


def block(header: str) -> list[tuple[str, str]]:
    """(local path, rea path) pairs under ``header``, up to the next blank line."""
    lines = _lines()
    assert header in lines, f"NOTICE has no '{header}' line"
    entries: list[tuple[str, str]] = []
    for line in lines[lines.index(header) + 1 :]:
        if not line.strip():
            break
        if line == NONE:
            continue
        m = ENTRY.match(line)
        assert m, f"NOTICE line does not match '  <local>  from <rea path>': {line!r}"
        entries.append((m.group(1), m.group(2)))
    return entries


def _marked_files() -> set[str]:
    found: set[str] = set()
    for top in SCAN_DIRS:
        for path in (ROOT / top).rglob("*"):
            if not path.is_file():
                continue
            try:
                with path.open(encoding="utf-8") as fh:
                    head = "".join(fh.readline() for _ in range(5))
            except UnicodeDecodeError:
                continue
            if MARKER in head:
                found.add(path.relative_to(ROOT).as_posix())
    return found


def test_blocks_present() -> None:
    block(ADAPTED)
    assert block(FIXTURES), f"NOTICE '{FIXTURES}' block is empty"


def test_listed_paths_exist() -> None:
    listed = [p for p, _ in block(ADAPTED) + block(FIXTURES)]
    missing = [p for p in listed if not (ROOT / p).exists()]
    assert not missing, f"NOTICE lists paths that do not exist: {missing}"


def test_fixture_entries_are_folders() -> None:
    bad = [p for p, _ in block(FIXTURES) if not (p.endswith("/") and (ROOT / p).is_dir())]
    assert not bad, f"verbatim fixture entries must be folders ending in '/': {bad}"


def test_marked_files_are_listed() -> None:
    unlisted = sorted(_marked_files() - {p for p, _ in block(ADAPTED)})
    assert not unlisted, f"files marked '{MARKER}' but absent from NOTICE: {unlisted}"


def test_none_yet_means_empty() -> None:
    lines = _lines()
    first = lines.index(ADAPTED) + 1
    if first < len(lines) and lines[first] == NONE:
        assert not block(ADAPTED), f"NOTICE says '{NONE.strip()}' but lists adapted files"
