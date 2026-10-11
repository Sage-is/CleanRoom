"""A worker for tests: run with ``python tests/fixtures/echo_worker.py``.

It registers one handler per behaviour the client must survive: a plain
echo, a sleep that outlives the deadline, an oversized reply, a stray print,
a Fail-like error with a chosen code, an unexpected exception and a progress
event written before the reply.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cleanroom import worker  # noqa: E402 - after the path fix


class WorkerError(Exception):
    """Fail-like without importing cleanroom.target, as an engine Python would."""

    def __init__(self, code: str, message: str, hint: str | None = None):
        super().__init__(message)
        self.code, self.message, self.hint = code, message, hint


def _fail(args: dict):
    raise WorkerError(args["code"], args.get("message", "as requested"), args.get("hint"))


def _boom(args: dict):
    raise RuntimeError(args.get("message", "kaboom"))


def _noisy(args: dict):
    print("stray")
    return 1


def _event(args: dict):
    worker.emit({"progress": args.get("progress", 1)})
    return "done"


HANDLERS = {
    "echo": lambda args: args,
    "sleep": lambda args: time.sleep(args["s"]),
    "big": lambda args: "x" * args["n"],
    "noisy": _noisy,
    "fail": _fail,
    "boom": _boom,
    "event": _event,
    "unserialisable": lambda args: object(),
}

if __name__ == "__main__":
    worker.serve(HANDLERS, "echo 1.0")
