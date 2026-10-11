"""Subprocesses: bounded one-shot runs and owned process groups (design section 6).

``run_limited`` never uses a shell, caps output, applies rlimits in the child and kills
the whole process group at the deadline. ``spawn_owned`` starts a long-running child in
its own session with an environment token; ``kill_owned`` verifies its identity with
psutil before signalling. P2 adds the token scan that finds detached grandchildren.
"""

from __future__ import annotations

import os
import resource
import signal
import subprocess
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass

import psutil

from cleanroom.target import Fail

TOKEN_VAR = "CLEANROOM_RUN_TOKEN"
RLIMITS = {"as": "RLIMIT_AS", "cpu": "RLIMIT_CPU", "fsize": "RLIMIT_FSIZE", "core": "RLIMIT_CORE"}
_CHUNK = 65536
_unreaped: list[
    subprocess.Popen
] = []  # leaders a kill could not wait for; polled on each spawn/kill


def _reap_pending() -> None:
    """Reap the leaders an earlier kill left behind: no zombie outlives the next spawn or kill."""
    _unreaped[:] = [p for p in _unreaped if p.poll() is None]


@dataclass
class Completed:
    """What a bounded run produced; ``truncated`` means output past max_out was dropped."""

    argv: list[str]
    returncode: int
    stdout: bytes
    stderr: bytes
    truncated: bool
    seconds: float


@dataclass
class Owned:
    """A long-running child we started: its Popen, its token and its psutil create time."""

    popen: subprocess.Popen
    token: str
    create_time: float


def _popen(argv: list[str], **kw) -> subprocess.Popen:
    """Start ``argv`` in its own session, never through a shell; a missing program is not_found."""
    if not argv:
        raise Fail("bad_input", "argv is empty")
    try:
        return subprocess.Popen(list(argv), start_new_session=True, **kw)
    except FileNotFoundError as e:
        what = e.filename or argv[0]
        raise Fail("not_found", f"cannot run {argv[0]!r}: {e.strerror}: {what}") from e
    except OSError as e:
        raise Fail("failed", f"cannot run {argv[0]!r}: {e.strerror or e}") from e


def _killpg(pgid: int, sig: int) -> None:
    """Signal a group we own. A vanished group, or one holding only zombies, raises nothing."""
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def _preexec(rlimits: dict) -> Callable[[], None]:
    """Build the child-side hook that applies ``rlimits``, skipping what the platform refuses."""

    def apply() -> None:
        for key, value in rlimits.items():
            name = RLIMITS[key]
            if not hasattr(resource, name):
                continue
            try:
                resource.setrlimit(getattr(resource, name), (value, value))
            except (ValueError, OSError):
                pass

    return apply


def _reader(pipe, max_out: int) -> tuple[threading.Thread, dict]:
    """Drain ``pipe`` on a thread, keeping the first ``max_out`` bytes and counting the rest."""
    box = {"data": bytearray(), "dropped": 0}

    def run() -> None:
        with pipe:
            while chunk := pipe.read1(_CHUNK):
                keep = max(0, min(len(chunk), max_out - len(box["data"])))
                box["data"] += chunk[:keep]
                box["dropped"] += len(chunk) - keep

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, box


def _write(pipe, data: bytes) -> None:
    """Feed stdin from a thread, so a child that never reads cannot deadlock us."""
    try:
        with pipe:
            pipe.write(data)
    except OSError:
        pass


def _finish(
    p: subprocess.Popen, readers: list[threading.Thread], deadline: float
) -> tuple[int, bool]:
    """Wait for output to close and the leader to exit; past the deadline, kill the group.

    Returns (exit code, killed). The leader is reaped only after any kill, so its pid, and
    with it the group id, cannot be reused while we signal.
    """
    for t in readers:
        t.join(max(0.0, deadline - time.monotonic()))
    killed = any(t.is_alive() for t in readers)
    if killed:
        _killpg(p.pid, signal.SIGKILL)
    try:
        rc = p.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        _killpg(p.pid, signal.SIGKILL)
        killed = True
        rc = p.wait()
    for t in readers:
        t.join(1.0)
    return rc, killed


def run_limited(
    argv: list[str],
    timeout: float = 60.0,
    max_out: int = 1 << 20,
    rlimits: dict | None = None,
    cwd: str | None = None,
    env: dict | None = None,
    stdin: bytes | None = None,
) -> Completed:
    """Run ``argv`` to completion under a deadline, an output cap and optional rlimits.

    No shell is involved. Output past ``max_out`` bytes per stream is dropped and reported
    through ``truncated``. When the deadline passes the whole process group is killed and
    Fail("timeout") is raised. ``rlimits`` keys are "as", "cpu", "fsize" and "core".
    """
    unknown = sorted(set(rlimits or ()) - RLIMITS.keys())
    if unknown:
        raise Fail("bad_input", f"unknown rlimit keys {unknown}", hint=f"use {sorted(RLIMITS)}")
    started = time.monotonic()
    p = _popen(
        argv,
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=env,
        preexec_fn=_preexec(rlimits) if rlimits else None,
    )
    out_t, out = _reader(p.stdout, max_out)
    err_t, err = _reader(p.stderr, max_out)
    if stdin is not None:
        threading.Thread(target=_write, args=(p.stdin, stdin), daemon=True).start()
    rc, killed = _finish(p, [out_t, err_t], started + timeout)
    seconds = time.monotonic() - started
    if killed and rc == -signal.SIGKILL:
        hint = "raise timeout, or narrow the input"
        raise Fail("timeout", f"{argv[0]} ran past {timeout:g}s and was killed", hint)
    truncated = bool(out["dropped"] or err["dropped"])
    return Completed(list(argv), rc, bytes(out["data"]), bytes(err["data"]), truncated, seconds)


def spawn_owned(
    argv: list[str],
    env: dict | None = None,
    cwd: str | None = None,
    stdin=None,
    stdout=None,
    stderr=None,
) -> Owned:
    """Start a long-running child in its own session, tagged with a fresh CLEANROOM_RUN_TOKEN."""
    _reap_pending()
    token = str(uuid.uuid4())
    env = dict(os.environ if env is None else env)
    env[TOKEN_VAR] = token
    p = _popen(argv, env=env, cwd=cwd, stdin=stdin, stdout=stdout, stderr=stderr)
    try:
        create_time = psutil.Process(p.pid).create_time()
    except psutil.Error:  # gone already: kill_owned then fails closed and only reaps
        create_time = 0.0
    return Owned(p, token, create_time)


def _same(o: Owned) -> bool:
    """True while the pid still belongs to the child we started (psutil create time matches)."""
    try:
        return o.create_time > 0 and psutil.Process(o.popen.pid).create_time() == o.create_time
    except psutil.Error:
        return False


def _exited(pid: int) -> bool:
    """True once the child has exited, without reaping it, so its pid stays ours."""
    try:
        return psutil.Process(pid).status() == psutil.STATUS_ZOMBIE
    except psutil.Error:
        return True


def kill_owned(o: Owned, grace: float = 0.5) -> None:
    """Stop an owned child and its process group: SIGTERM, wait ``grace``, SIGKILL, reap.

    Fails closed: when the pid no longer matches the child we started, nothing is signalled
    and the child is only reaped. The leader is reaped last, so the group id cannot be
    reused while we signal it.
    """
    _reap_pending()
    p = o.popen
    if p.returncode is not None or not _same(o):
        p.poll()
        return
    _killpg(p.pid, signal.SIGTERM)
    end = time.monotonic() + grace
    while time.monotonic() < end and not _exited(p.pid):
        time.sleep(0.02)
    _killpg(p.pid, signal.SIGKILL)
    try:
        p.wait(timeout=grace)
    except subprocess.TimeoutExpired:  # stuck in the kernel; the next spawn or kill reaps it
        _unreaped.append(p)
