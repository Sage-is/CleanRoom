"""Command line entry point.

Stub: P0.6 replaces this with the argparse parser generated from the tool
registry. Until then only `cleanroom version` works.
"""

import sys

from cleanroom import __version__


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args[:1] == ["version"]:
        print(f"cleanroom {__version__}")
        return 0
    print("cleanroom: CLI not built yet (P0.6)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
