"""Engine probes shared by ``cleanroom doctor`` and the test suite.

Each probe returns a short string (a version or a path) when the engine is
usable on this machine, or ``None`` when it is not. Only the standard library
is imported at module load; ``lief`` and ``capstone`` load inside the builtin
probe so this module stays cheap to import.
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

_HOPPER_APPS = tuple(f"/Applications/Hopper Disassembler v{n}.app" for n in (4, 5, 6))


def xcode_tools() -> bool:
    """True when ``xcode-select -p`` finds developer tools.

    Without them, ``/usr/bin/cc`` and ``/usr/bin/lldb`` are shims that prompt
    for an install instead of running.
    """
    if sys.platform != "darwin":
        return True
    done = subprocess.run(["xcode-select", "-p"], capture_output=True, check=False)
    return done.returncode == 0


def _env_dir(var: str) -> str | None:
    value = os.environ.get(var)
    return value if value and os.path.isdir(value) else None


def _has_module(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _env_and_module(var: str, module: str) -> str | None:
    path = _env_dir(var)
    return path if path and _has_module(module) else None


def _hopper() -> str | None:
    if sys.platform == "darwin":
        for app in _HOPPER_APPS:
            if Path(app).is_dir():
                return app
    return shutil.which("hopper")


def _lldb() -> str | None:
    path = shutil.which("lldb")
    return path if path and xcode_tools() else None


def _playwright() -> str | None:
    """The chromium path, only once ``playwright install chromium`` has run."""
    if not _has_module("playwright"):
        return None
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        path = p.chromium.executable_path
    return path if Path(path).exists() else None


def _builtin() -> str:
    # Distribution versions: capstone's module constant lags its wheel and
    # lief's carries a commit hash.
    lief = importlib.metadata.version("lief")
    capstone = importlib.metadata.version("capstone")
    return f"lief {lief} + capstone {capstone}"


PROBES: dict[str, Callable[[], str | None]] = {
    "ghidra": lambda: _env_and_module("GHIDRA_INSTALL_DIR", "pyghidra"),
    "ida": lambda: _env_and_module("IDADIR", "idapro"),
    "hopper": _hopper,
    "lldb": _lldb,
    "jadx": lambda: shutil.which("jadx"),
    # The `unblob` marker means "a firmware extractor": either tool will do.
    "unblob": lambda: shutil.which("unblob") or shutil.which("binwalk"),
    "binwalk": lambda: shutil.which("binwalk"),
    "playwright": _playwright,
    "builtin": _builtin,
}


def probe(name: str) -> str | None:
    """Return a version or path for engine ``name``, or ``None`` if absent."""
    try:
        return PROBES[name]()
    except Exception:  # noqa: BLE001 - a broken engine counts as missing
        return None


def probe_all() -> dict[str, str | None]:
    """Probe every known engine; keys follow ``PROBES`` order."""
    return {name: probe(name) for name in PROBES}
