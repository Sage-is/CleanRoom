"""CleanRoom: reverse-engineer anything, locally.

A DRY/KISS reimplementation of morluto/rea (MIT) for Python 3.12: one tool
registry, one Evidence type, one module per target kind and one worker
protocol. The design lives in docs/design.md.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cleanroom-re")
except PackageNotFoundError:  # a checkout that was never installed
    __version__ = "0.0.0"
