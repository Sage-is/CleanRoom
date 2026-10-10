"""Line budget per docs/design.md section 8: limits, not targets."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "cleanroom"

BUDGET = {
    "cleanroom/__main__.py": 200,
    "cleanroom/tools.py": 450,
    "cleanroom/evidence.py": 300,
    "cleanroom/target.py": 220,
    "cleanroom/proc.py": 300,
    "cleanroom/worker.py": 180,
    "cleanroom/graph.py": 250,
    "cleanroom/kinds/native.py": 600,
    "cleanroom/kinds/js.py": 1100,
    "cleanroom/kinds/web.py": 400,
    "cleanroom/kinds/har.py": 120,
    "cleanroom/kinds/dotnet.py": 800,
    "cleanroom/kinds/android.py": 250,
    "cleanroom/kinds/firmware.py": 250,
    "cleanroom/kinds/apple.py": 450,
    "cleanroom/kinds/evm.py": 60,
    "cleanroom/kinds/process.py": 320,
    "cleanroom/engines/__init__.py": 100,
    "cleanroom/engines/ghidra_worker.py": 450,
    "cleanroom/engines/ida_worker.py": 300,
}
ADAPTED = {
    "cleanroom/engines/hopper_bridge.py",
    "cleanroom/engines/rea_lldb_tracer.py",
}
# The per-file caps sum to 7,100: they are individual limits that cannot all be
# reached at once, and the total binds first (design section 8).
TOTAL = 7000
INIT_CAP = 30


def count(path: Path) -> int:
    """Lines that are neither blank nor comments."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return sum(1 for ln in lines if ln.strip() and not ln.strip().startswith("#"))


def _sources() -> list[str]:
    return sorted(p.relative_to(ROOT).as_posix() for p in PKG.rglob("*.py"))


def _cap(rel: str) -> int | None:
    if rel in BUDGET:
        return BUDGET[rel]
    if rel in ADAPTED:
        return None
    if rel.endswith("/__init__.py"):
        return INIT_CAP
    raise AssertionError(f"{rel} is not in BUDGET, ADAPTED or an __init__.py")


def test_every_source_is_budgeted() -> None:
    for rel in _sources():
        _cap(rel)


def test_each_file_within_cap() -> None:
    over = []
    for rel in _sources():
        cap = _cap(rel)
        if cap is None:
            continue
        n = count(ROOT / rel)
        if n > cap:
            over.append(f"{rel}: {n} > {cap}")
    assert not over, "over budget: " + ", ".join(over)


def test_total_within_budget() -> None:
    counted = {rel: count(ROOT / rel) for rel in _sources() if _cap(rel) is not None}
    total = sum(counted.values())
    assert total <= TOTAL, f"budget: {total}/{TOTAL} lines across {len(counted)} files"
    print(f"budget: {total}/{TOTAL} lines across {len(counted)} files")
