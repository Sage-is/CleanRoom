"""proc.py: bounded runs, output caps, rlimits, owned process groups."""

from __future__ import annotations

import os
import resource
import signal
import subprocess
import sys
import time

import psutil
import pytest

from cleanroom.proc import TOKEN_VAR, Completed, Owned, kill_owned, run_limited, spawn_owned
from cleanroom.target import Fail

PY = sys.executable


def _survivors(argv: list[str], since: float, pgid: int | None = None) -> list[psutil.Process]:
    """Live processes running exactly ``argv`` that were created after ``since`` (epoch)."""
    found = []
    for p in psutil.process_iter(["cmdline", "create_time", "status"]):
        try:
            if p.info["cmdline"] != argv or p.info["create_time"] < since - 2:
                continue
            if p.info["status"] == psutil.STATUS_ZOMBIE:
                continue
            if pgid is not None and os.getpgid(p.pid) != pgid:
                continue
            found.append(p)
        except (psutil.Error, OSError):
            continue
    return found


def _settle(pred, timeout: float = 2.0, step: float = 0.05) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(step)
    return pred()


def _reap(procs: list[psutil.Process]) -> None:
    for p in procs:
        try:
            p.kill()
        except psutil.Error:
            pass


# run_limited


def test_timeout_kills_group_and_returns_fast() -> None:
    argv = ["sleep", "10"]
    since = time.time()
    t0 = time.monotonic()
    with pytest.raises(Fail) as e:
        run_limited(argv, timeout=0.5)
    assert e.value.code == "timeout"
    assert time.monotonic() - t0 < 1.5
    assert _settle(lambda: not _survivors(argv, since), 1.0), "sleep survived the kill"


def test_output_cap_reports_truncation() -> None:
    c = run_limited(["sh", "-c", "yes | head -c 5000000"], max_out=1024)
    assert isinstance(c, Completed)
    assert c.returncode == 0
    assert c.truncated is True
    assert len(c.stdout) == 1024
    assert c.stdout == b"y\n" * 512


def test_small_output_is_not_truncated() -> None:
    c = run_limited(["echo", "hi"], max_out=1024)
    assert c.stdout == b"hi\n"
    assert c.truncated is False
    assert c.stderr == b""
    assert 0 <= c.seconds < 5


def test_no_shell_is_used() -> None:
    c = run_limited(["echo", "a;b"])
    assert c.stdout == b"a;b\n"
    assert c.argv == ["echo", "a;b"]


def test_missing_executable_is_not_found() -> None:
    with pytest.raises(Fail) as e:
        run_limited(["/nonexistent/cleanroom-no-such-binary"])
    assert e.value.code == "not_found"


def test_empty_argv_is_bad_input() -> None:
    with pytest.raises(Fail) as e:
        run_limited([])
    assert e.value.code == "bad_input"


def test_unknown_rlimit_key_is_bad_input() -> None:
    with pytest.raises(Fail) as e:
        run_limited(["true"], rlimits={"ram": 1})
    assert e.value.code == "bad_input"


def test_stdin_bytes_reach_the_child() -> None:
    c = run_limited(["cat"], stdin=b"hello\n")
    assert c.stdout == b"hello\n"


def test_stderr_is_captured_separately() -> None:
    c = run_limited([PY, "-c", "import sys; sys.stderr.write('oops'); sys.exit(3)"])
    assert c.returncode == 3
    assert c.stderr == b"oops"
    assert c.stdout == b""


def test_rlimit_cpu_kills_busy_loop() -> None:
    if not hasattr(resource, "RLIMIT_CPU"):
        pytest.skip("RLIMIT_CPU unsupported")
    probe = subprocess.run(
        [PY, "-c", "import resource as r; r.setrlimit(r.RLIMIT_CPU, (1, 1))"],
        capture_output=True,
    )
    if probe.returncode != 0:
        pytest.skip("setrlimit RLIMIT_CPU refused on this platform")
    c = run_limited([PY, "-c", "while True: pass"], timeout=10, rlimits={"cpu": 1})
    assert c.returncode in (-signal.SIGXCPU, -signal.SIGKILL)
    assert c.seconds < 6


def test_rlimit_refused_by_platform_is_skipped() -> None:
    # RLIMIT_AS is refused on macOS and honoured on Linux; the run must succeed on both.
    c = run_limited(["echo", "ok"], rlimits={"as": 1 << 30, "core": 0})
    assert c.stdout == b"ok\n"


# spawn_owned / kill_owned


def test_spawn_owned_sets_token_in_child_env() -> None:
    o = spawn_owned(
        [PY, "-c", f"import os; print(os.environ[{TOKEN_VAR!r}])"], stdout=subprocess.PIPE
    )
    try:
        assert isinstance(o, Owned)
        line = o.popen.stdout.readline().decode().strip()
        assert line == o.token
        assert len(o.token) == 36
        assert o.create_time > 0
    finally:
        o.popen.stdout.close()
        o.popen.wait(timeout=5)


def test_spawn_owned_keeps_caller_env() -> None:
    o = spawn_owned(
        [PY, "-c", "import os; print(os.environ.get('CLEANROOM_PROBE', ''))"],
        env={"CLEANROOM_PROBE": "yes", "PATH": os.environ.get("PATH", "")},
        stdout=subprocess.PIPE,
    )
    try:
        assert o.popen.stdout.readline().decode().strip() == "yes"
    finally:
        o.popen.stdout.close()
        o.popen.wait(timeout=5)


def test_kill_owned_kills_grandchildren_in_group() -> None:
    script = "sleep 30 & sleep 30" if sys.platform == "darwin" else "setsid sleep 30 & sleep 30"
    sleeper = ["sleep", "30"]
    since = time.time()
    o = spawn_owned(["sh", "-c", script])
    pgid = o.popen.pid
    try:
        assert _settle(lambda: len(_survivors(sleeper, since)) >= 2, 3.0), (
            "children never appeared"
        )
        t0 = time.monotonic()
        kill_owned(o)
        assert time.monotonic() - t0 < 2.0
        assert o.popen.returncode is not None, "leader was not reaped"
        assert _settle(lambda: not _survivors(sleeper, since, pgid), 1.0), "group members survived"
    finally:
        _reap(_survivors(sleeper, since))  # the setsid grandchild on Linux: P2's scan owns it


def test_kill_owned_on_exited_and_reaped_child_is_noop() -> None:
    o = spawn_owned(["true"])
    o.popen.wait(timeout=5)
    assert kill_owned(o) is None
    assert o.popen.returncode == 0


def test_kill_owned_on_zombie_reaps_it() -> None:
    o = spawn_owned(["true"])
    assert _settle(lambda: psutil.Process(o.popen.pid).status() == psutil.STATUS_ZOMBIE, 3.0)
    assert kill_owned(o) is None
    assert o.popen.returncode == 0


def test_kill_owned_fails_closed_on_identity_mismatch() -> None:
    o = spawn_owned(["sleep", "5"])
    try:
        stale = Owned(o.popen, o.token, o.create_time + 1.0)
        kill_owned(stale, grace=0.1)
        assert o.popen.poll() is None, "signalled a process whose identity did not match"
    finally:
        kill_owned(o, grace=0.1)
        assert o.popen.returncode is not None


def test_kill_owned_sigterm_is_tried_before_sigkill() -> None:
    code = "import signal,time; signal.signal(signal.SIGTERM, lambda *_: exit(42)); time.sleep(30)"
    o = spawn_owned([PY, "-c", code])
    assert _settle(lambda: psutil.Process(o.popen.pid).status() == psutil.STATUS_SLEEPING, 3.0)
    time.sleep(0.2)  # let the handler install
    kill_owned(o, grace=1.0)
    assert o.popen.returncode == 42
