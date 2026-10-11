"""Targets: the one failure type, file identity, kind detection and ref parsing.

Every other module imports Fail from here. Below it: Target, the digest helpers,
kind detection over KIND_ORDER, open_target and parse_ref.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import struct
from dataclasses import dataclass
from pathlib import Path

CODES = (
    "bad_input",
    "not_found",
    "ambiguous",
    "unsupported",
    "engine_missing",
    "timeout",
    "too_big",
    "failed",
)


class Fail(Exception):
    """The single error type. The CLI prints it as JSON and exits 1; MCP sets is_error."""

    def __init__(self, code: str, message: str, hint: str | None = None):
        if code not in CODES:
            raise ValueError(f"unknown Fail code {code!r}")
        super().__init__(message)
        self.code = code
        self.message = message
        self.hint = hint

    def to_dict(self) -> dict:
        d = {"code": self.code, "message": self.message}
        if self.hint:
            d["hint"] = self.hint
        return d

    def __str__(self) -> str:
        return f"{self.code}: {self.message}" + (f" ({self.hint})" if self.hint else "")


# Most specific first (design section 3). "evm" is never detected: it must be named.
KIND_ORDER = ("web", "har", "process", "dotnet", "android", "apple", "js", "native", "firmware")
HEAD_BYTES = 4096
# FAT and FAT64 Mach-O magics. Java class files share CAFEBABE; see is_fat_macho.
FAT_MAGICS = (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")
MAX_FAT_ARCH = 30


@dataclass(frozen=True)
class Target:
    """A bound target: where it is, what it hashes to, how big it is and which kind owns it."""

    path: str
    sha256: str
    size: int
    kind: str


def cache_dir() -> Path:
    """``$CLEANROOM_CACHE`` or ``~/.cache/cleanroom``, created on first use."""
    base = os.environ.get("CLEANROOM_CACHE") or os.path.join(
        os.path.expanduser("~"), ".cache", "cleanroom"
    )
    path = Path(base)
    path.mkdir(parents=True, exist_ok=True)
    return path


def is_url(path: str) -> bool:
    return path.startswith(("http://", "https://"))


def _kind_module(kind: str):
    """The kind module, or None when it is not installed yet (kinds land one at a time)."""
    try:
        return importlib.import_module(f"cleanroom.kinds.{kind}")
    except ImportError:  # includes ModuleNotFoundError
        return None


def installed_kinds() -> list[str]:
    """The kinds whose module imports today, in detection order, then evm when present."""
    return [k for k in (*KIND_ORDER, "evm") if _kind_module(k) is not None]


def unavailable(kind: str) -> Fail:
    """The failure for a kind that is named or detected but not installed in this build."""
    have = ", ".join(installed_kinds()) or "none"
    return Fail("unsupported", f"kind {kind!r} is not available yet", f"installed: {have}")


def sha256_file(path: str) -> str:
    """Digest of the whole file.

    A file that changes while it is read gets no digest at all (design section 9,
    case 20): the stat before and after must agree.
    """
    before = os.stat(path)
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            digest.update(chunk)
    after = os.stat(path)
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise Fail("failed", f"{path} changed while it was hashed", "retry once it is stable")
    return digest.hexdigest()


def _sha256_dir(path: str) -> tuple[str, int]:
    """Identity of a directory target: a digest over relative paths and sizes, plus total bytes.

    Contents are not read; a bundle or an unpacked app can run to gigabytes. Symlinks
    are listed by name only and never followed.
    """
    digest, total = hashlib.sha256(), 0
    for root, dirs, files in os.walk(path):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(root, name)
            size = 0 if os.path.islink(full) else os.path.getsize(full)
            total += size
            digest.update(f"{os.path.relpath(full, path)}\0{size}\n".encode())
    return digest.hexdigest(), total


def read_head(path: str, n: int = HEAD_BYTES) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def is_fat_macho(head: bytes) -> bool:
    """True for a FAT Mach-O header: CAFEBABE or CAFEBABF with 1 <= nfat_arch <= 30.

    A Java class file starts with the same magic; its next four bytes are the
    minor and major version, which read as an nfat_arch of 45 or more.
    """
    if len(head) < 8 or head[:4] not in FAT_MAGICS:
        return False
    return 1 <= struct.unpack(">I", head[4:8])[0] <= MAX_FAT_ARCH


def detect(path: str, head: bytes) -> str | None:
    """The first kind in KIND_ORDER whose module exists and whose detect() claims the target."""
    for kind in KIND_ORDER:
        module = _kind_module(kind)
        claims = getattr(module, "detect", None)
        if claims is not None and claims(path, head):
            return kind
    return None


def open_target(path: str, kind: str | None = None) -> Target:
    """Identify a path or URL and bind it to a kind.

    ``kind`` overrides detection (the only way to open EVM bytecode). A URL is always
    ``web``; its digest is the digest of the URL text and its size is 0.
    """
    if is_url(path):
        if kind not in (None, "web"):
            raise Fail("bad_input", f"a URL is kind web, not {kind!r}")
        return Target(path, hashlib.sha256(path.encode()).hexdigest(), 0, "web")
    full = os.path.abspath(path)  # as given: no ~user expansion, the shell did that already
    if not os.path.exists(full):
        raise Fail("not_found", f"{path} does not exist")
    is_file = os.path.isfile(full)
    if not is_file and not os.path.isdir(full):
        raise Fail("unsupported", f"{path} is not a regular file or a directory")
    try:
        head = read_head(full) if is_file else b""
        if kind is None:
            kind = detect(full, head)
            if kind is None:
                have = ", ".join(installed_kinds()) or "none"
                hint = f"pass kind= ({have}); other kinds are not installed yet"
                raise Fail("unsupported", f"no kind recognises {path}", hint)
        elif not kind.isidentifier() or _kind_module(kind) is None:
            raise unavailable(kind)
        sha, size = (sha256_file(full), os.path.getsize(full)) if is_file else _sha256_dir(full)
    except OSError as e:
        raise Fail("failed", f"cannot read {path}: {e.strerror or e}") from e
    return Target(full, sha, size, kind)


def parse_ref(ref: str) -> tuple:
    """``("addr", int, space | None)`` for ``0x..`` or ``space:0x..``; else ``("name", ref)``.

    Only an explicit ``0x`` makes an address: ``add`` and ``face`` are valid hex but
    stay names, and a kind resolves them as symbols first (design section 9, case 1).
    """
    ref = ref.strip()
    space, _, tail = ref.rpartition(":")
    if tail[:2].lower() != "0x":
        return ("name", ref)
    try:
        return ("addr", int(tail, 16), space or None)
    except ValueError:
        raise Fail("bad_input", f"{ref!r} is not a hex address") from None
