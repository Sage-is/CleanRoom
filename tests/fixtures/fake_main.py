"""The cleanroom CLI with the fake kind registered: ``python tests/fixtures/fake_main.py ARGS``.

The CLI and MCP tests run the real entry point in a subprocess; this wrapper puts
``tests/fixtures/fake_kind`` in front of detection first, so no test hook has to
live in the production entry point.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cleanroom import target  # noqa: E402 - after the path fix
from tests.fixtures import fake_kind  # noqa: E402

sys.modules["cleanroom.kinds.fake"] = fake_kind
target.KIND_ORDER = ("fake", *target.KIND_ORDER)

if __name__ == "__main__":
    from cleanroom.__main__ import main

    sys.exit(main())
