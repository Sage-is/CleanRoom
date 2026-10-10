"""Shared pytest fixtures: compiled C fixtures and engine auto-skip."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import warnings
from pathlib import Path

import pytest

from cleanroom.engines import probe, xcode_tools

FIXTURES = Path(__file__).parent / "fixtures"
ENGINE_MARKERS = ("ghidra", "ida", "hopper", "lldb", "jadx", "unblob", "playwright")
_CFLAGS = ["-O0", "-g", "-fno-inline"]


def _compile(src: Path, out: Path) -> Path:
    """Build ``src`` into ``out`` with cc; FAT on macOS, single-arch elsewhere.

    When the two-arch build fails (no x86_64 SDK slice, older tools) the thin
    fallback is used and a warning names it, so a FAT-specific assertion that
    then fails is traceable to the fixture, not the code under test.
    """
    cc = shutil.which("cc")
    if cc is None:
        pytest.skip("cc not found")
    if not xcode_tools():
        pytest.skip("cc is the xcode-select shim; no developer tools installed")
    attempts = [[cc, *_CFLAGS, "-o", str(out), str(src)]]
    if sys.platform == "darwin":
        fat = [cc, *_CFLAGS, "-arch", "arm64", "-arch", "x86_64", "-o", str(out), str(src)]
        attempts.insert(0, fat)
    last = None
    for cmd in attempts:
        last = subprocess.run(cmd, capture_output=True, text=True)
        if last.returncode == 0:
            return out
        if "-arch" in cmd:
            warnings.warn(
                f"FAT build of {src.name} failed, fixture is thin: {last.stderr.strip()}",
                stacklevel=2,
            )
    raise RuntimeError(f"cc failed for {src.name}: {last.stderr if last else ''}")


@pytest.fixture(scope="session")
def build_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("build")


@pytest.fixture(scope="session")
def c_fixture(build_dir: Path) -> Path:
    return _compile(FIXTURES / "c" / "fixture.c", build_dir / "fixture")


@pytest.fixture(scope="session")
def c_v1(build_dir: Path) -> Path:
    return _compile(FIXTURES / "c" / "v1.c", build_dir / "v1")


@pytest.fixture(scope="session")
def c_v2(build_dir: Path) -> Path:
    return _compile(FIXTURES / "c" / "v2.c", build_dir / "v2")


def pytest_runtest_setup(item: pytest.Item) -> None:
    required = {n.strip() for n in os.environ.get("CLEANROOM_REQUIRE_ENGINES", "").split(",")}
    for name in ENGINE_MARKERS:
        if item.get_closest_marker(name) is None or probe(name) is not None:
            continue
        if name in required:
            pytest.fail(f"engine {name} required but not found")
        pytest.skip(f"engine {name} not found")
