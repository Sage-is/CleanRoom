"""The JSON-lines worker protocol: ``serve`` for the worker, ``Worker`` for the client.

Engine Pythons run ``serve`` too, so only the standard library loads at import;
``cleanroom.proc`` and ``cleanroom.target`` load lazily inside ``Worker``. One
object per line: the ready line ``{"id": 0, "result": {"ready": true, "engine"}}``,
then ``{"id", "op", "args"}`` answered by ``{"id", "result"}`` or ``{"id", "error":
{"code", "message", "hint"}}``. A line carrying ``"event"`` is progress; clients skip it.
"""

from __future__ import annotations

import contextlib
import json
import os
import select
import signal
import subprocess
import sys
import threading
import time
import traceback
from collections.abc import Callable
from typing import Any

MAX_LINE = 64 << 20  # a reply line over this fails too_big
_CHUNK = 1 << 20
_out = None  # the worker's protocol stream, set by serve()


def _error(code: str, message: str, hint: str | None = None) -> dict:
    return {"code": code, "message": message, "hint": hint}


def _send(obj: Any) -> None:
    _out.write(json.dumps(obj).encode() + b"\n")
    _out.flush()


def emit(event: Any) -> None:
    """Worker side: send a progress line ``{"event": ...}``; clients skip it."""
    if _out is not None:
        _send({"event": event})


def _handle(handlers: dict[str, Callable[[dict], Any]], req: dict) -> dict:
    """Run one request; an exception becomes an error reply, keeping a Fail-like ``code``."""
    fn = handlers.get(req.get("op"))
    if fn is None:
        return {"error": _error("unsupported", f"unknown op {req.get('op')!r}")}
    try:
        return {"result": fn(req.get("args") or {})}
    except Exception as exc:  # noqa: BLE001 - the worker must keep serving
        code = getattr(exc, "code", None)
        if not isinstance(code, str):
            code = "failed"
            traceback.print_exc()
        message = getattr(exc, "message", None) or str(exc) or type(exc).__name__
        return {"error": _error(code, message, getattr(exc, "hint", None))}


def serve(handlers: dict[str, Callable[[dict], Any]], engine: str) -> None:
    """Worker side: answer requests on a copy of fd 1 until stdin closes; prints go to stderr."""
    global _out
    sys.stdout.flush()
    _out = os.fdopen(os.dup(1), "wb")
    os.dup2(2, 1)
    _send({"id": 0, "result": {"ready": True, "engine": engine}})
    for raw in sys.stdin.buffer:
        if not raw.strip():
            continue
        try:
            req = json.loads(raw)
            if not isinstance(req, dict):
                raise ValueError("request is not a JSON object")
        except ValueError as exc:
            _send({"id": None, "error": _error("bad_input", f"malformed request: {exc}")})
            continue
        try:
            _send({"id": req.get("id"), **_handle(handlers, req)})
        except (TypeError, ValueError) as exc:
            _send({"id": req.get("id"), "error": _error("failed", f"result is not JSON: {exc}")})


def _fail(code: str, message: str, hint: str | None = None) -> Exception:
    from cleanroom.target import Fail

    return Fail(code, message, hint)


def _killpg(popen: subprocess.Popen, grace: float = 0.5) -> None:
    """Fallback when ``cleanroom.proc`` is absent: no create-time check, no token."""
    if popen.poll() is not None:
        return
    for sig, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, None)):
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(popen.pid, sig)
        with contextlib.suppress(subprocess.TimeoutExpired):
            popen.wait(wait)


class Worker:
    """Client for one worker; calls are serialised, and a kill makes the next call respawn.

    A missed deadline or a reply over ``MAX_LINE`` kills the whole process group.
    """

    def __init__(self, argv: list[str], env: dict | None = None, startup: float = 60.0):
        self.argv, self.env, self.startup = list(argv), env, startup
        self.engine = ""
        self._popen: subprocess.Popen | None = None
        self._owned = None
        self._buf = bytearray()
        self._seq = 0
        self._lock = threading.Lock()
        with self._lock:
            self._start()

    def _start(self) -> None:
        self._buf.clear()
        std = {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE}
        try:
            from cleanroom import proc

            self._owned = proc.spawn_owned(self.argv, env=self.env, **std)
            self._popen = self._owned.popen
        except ImportError:  # proc.py absent: plain Popen, see _killpg
            self._popen = subprocess.Popen(self.argv, env=self.env, start_new_session=True, **std)
        ready = self._reply(0, time.monotonic() + self.startup)
        self.engine = str((ready.get("result") or {}).get("engine", ""))

    def alive(self) -> bool:
        return self._popen is not None and self._popen.poll() is None

    def kill(self) -> None:
        """Stop the worker and its process group; ``call`` starts a fresh one later."""
        popen, owned, self._popen, self._owned = self._popen, self._owned, None, None
        if popen is None:
            return
        if owned is not None:
            from cleanroom import proc

            proc.kill_owned(owned)
        else:
            _killpg(popen)
        for stream in (popen.stdin, popen.stdout):
            if stream is not None:
                stream.close()

    def call(self, op: str, args: dict, timeout: float = 120.0) -> Any:
        """Send one request and return its result; a worker error becomes a ``Fail``."""
        from cleanroom.target import CODES

        with self._lock:
            if not self.alive():
                self._start()
            self._seq += 1
            line = json.dumps({"id": self._seq, "op": op, "args": args}).encode() + b"\n"
            try:
                self._popen.stdin.write(line)
                self._popen.stdin.flush()
            except (OSError, ValueError) as exc:
                self.kill()
                raise _fail("failed", f"worker {self.argv[0]} is gone: {exc}") from None
            msg = self._reply(self._seq, time.monotonic() + timeout)
        if "error" not in msg:
            return msg.get("result")
        err = msg["error"] if isinstance(msg["error"], dict) else {}
        code = err.get("code")
        message = str(err.get("message") or f"worker error {code!r}")
        raise _fail(code if code in CODES else "failed", message, err.get("hint"))

    def _reply(self, rid: int, deadline: float) -> dict:
        """The reply to request ``rid``; events and stale ids are skipped."""
        while True:
            raw = self._line(deadline)
            try:
                msg = json.loads(raw)
                if not isinstance(msg, dict):
                    raise ValueError("not a JSON object")
            except ValueError as exc:
                self.kill()
                raise _fail("failed", f"worker sent a malformed line: {exc}") from None
            if "event" not in msg and msg.get("id") == rid:
                return msg

    def _line(self, deadline: float) -> bytes:
        """One line from the worker, or kill it and fail timeout, too_big or failed."""
        popen = self._popen
        fd, poll = popen.stdout.fileno(), select.poll()  # poll: no FD_SETSIZE ceiling
        poll.register(fd, select.POLLIN)
        scanned = 0
        while True:
            nl = self._buf.find(b"\n", scanned)
            if nl >= 0:
                line = bytes(self._buf[:nl])
                del self._buf[: nl + 1]
                return line
            scanned = len(self._buf)
            if scanned > MAX_LINE:
                self.kill()
                raise _fail("too_big", f"worker reply exceeds {MAX_LINE} bytes")
            wait = deadline - time.monotonic()
            if wait <= 0 or not poll.poll(wait * 1000):
                self.kill()
                hint = "the worker was killed; the next call starts a new one"
                raise _fail("timeout", "worker did not reply within the deadline", hint)
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                self.kill()
                raise _fail("failed", f"worker exited with code {popen.returncode}")
            self._buf += chunk
