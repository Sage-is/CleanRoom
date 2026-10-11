"""worker.py: the JSON-lines loop and its client, driven by tests/fixtures/echo_worker.py."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import psutil
import pytest

from cleanroom.target import Fail
from cleanroom.worker import MAX_LINE, Worker

ECHO = [sys.executable, str(Path(__file__).parent / "fixtures" / "echo_worker.py")]


def _group_alive(pgid: int) -> bool:
    """True when any process still belongs to process group ``pgid``."""
    for p in psutil.process_iter(["pid"]):
        try:
            if os.getpgid(p.pid) == pgid:
                return True
        except (OSError, psutil.Error):
            continue
    return False


@pytest.fixture
def w(tmp_path, monkeypatch):
    monkeypatch.setenv("CLEANROOM_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("CLEANROOM_LEDGER", str(tmp_path / "ledger.jsonl"))
    worker = Worker(ECHO)
    yield worker
    worker.kill()


def test_round_trip_and_engine(w):
    assert w.engine == "echo 1.0"
    assert w.alive()
    args = {"n": 1, "s": "é😀", "nested": {"a": [1, 2.5, None, True]}}
    assert w.call("echo", args) == args
    assert w.call("echo", {}) == {}


def test_worker_is_its_own_process_group(w):
    pid = w._popen.pid
    assert os.getpgid(pid) == pid
    assert "CLEANROOM_RUN_TOKEN" not in os.environ


def test_stray_print_does_not_corrupt_framing(w):
    assert w.call("noisy", {}) == 1
    assert w.call("echo", {"after": "noise"}) == {"after": "noise"}


def test_fail_like_error_keeps_its_code(w):
    with pytest.raises(Fail) as info:
        w.call("fail", {"code": "unsupported", "message": "no pseudo", "hint": "use asm"})
    assert info.value.code == "unsupported"
    assert info.value.message == "no pseudo"
    assert info.value.hint == "use asm"
    assert w.alive(), "an error reply must not kill the worker"


def test_unknown_error_code_maps_to_failed(w):
    with pytest.raises(Fail) as info:
        w.call("fail", {"code": "weird"})
    assert info.value.code == "failed"


def test_unknown_op_is_unsupported(w):
    with pytest.raises(Fail) as info:
        w.call("nope", {})
    assert info.value.code == "unsupported"
    assert "nope" in info.value.message


def test_exception_in_handler_is_failed_with_message(w):
    with pytest.raises(Fail) as info:
        w.call("boom", {"message": "kaboom"})
    assert info.value.code == "failed"
    assert info.value.message == "kaboom"
    assert w.call("echo", {"still": "alive"}) == {"still": "alive"}


def test_unserialisable_result_is_failed(w):
    with pytest.raises(Fail) as info:
        w.call("unserialisable", {})
    assert info.value.code == "failed"
    assert w.alive()


def test_deadline_kills_group_and_next_call_respawns(w):
    pid = w._popen.pid
    started = time.monotonic()
    with pytest.raises(Fail) as info:
        w.call("sleep", {"s": 5}, timeout=0.5)
    elapsed = time.monotonic() - started
    assert info.value.code == "timeout"
    assert elapsed < 1.5, f"timeout took {elapsed:.2f}s"
    assert not w.alive()
    deadline = time.monotonic() + 1.0
    while _group_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not psutil.pid_exists(pid)
    assert not _group_alive(pid)
    assert w.call("echo", {"back": True}) == {"back": True}
    assert w._popen.pid != pid
    assert w.engine == "echo 1.0"


def test_oversized_reply_is_too_big(w):
    assert MAX_LINE == 64 * 1024 * 1024
    pid = w._popen.pid
    with pytest.raises(Fail) as info:
        w.call("big", {"n": 70_000_000})
    assert info.value.code == "too_big"
    assert not w.alive()
    assert not psutil.pid_exists(pid)
    assert w.call("big", {"n": 1000}) == "x" * 1000


def test_event_lines_are_skipped(w):
    assert w.call("event", {"progress": 3}) == "done"
    assert w.call("echo", {"k": "v"}) == {"k": "v"}


def test_kill_then_alive_is_false(w):
    pid = w._popen.pid
    w.kill()
    assert not w.alive()
    assert not psutil.pid_exists(pid)
    w.kill()  # idempotent
    assert w.call("echo", {"x": 1}) == {"x": 1}


def test_dead_worker_is_failed_then_respawns(w):
    w._popen.kill()
    w._popen.wait()
    assert not w.alive()
    assert w.call("echo", {"x": 2}) == {"x": 2}


def test_startup_deadline():
    with pytest.raises(Fail) as info:
        Worker([sys.executable, "-c", "import time; time.sleep(5)"], startup=0.3)
    assert info.value.code in ("timeout", "failed")


def test_worker_imports_only_stdlib_at_import():
    code = (
        "import sys; import cleanroom.worker; "
        "print(sorted(m for m in sys.modules if m.startswith('cleanroom')))"
    )
    import subprocess

    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "['cleanroom', 'cleanroom.worker']"
