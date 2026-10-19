"""A synthetic SCI game for the sci kind tests, written into a directory. No Sierra data.

``build(root, method=0, version="SCI0")`` writes ``resource.map`` and ``resource.000`` with
one script and vocabs 996, 997 and 999. ``method`` 1 or 2 stores every resource compressed
under that generation's meaning of the number. The encoders emit literals only, a stream
every SCI decoder must accept. ``asm`` assembles ``(mnemonic, operands, small)`` tuples.

Script 0 holds class ``Obj`` (properties species, superClass, -info-, name, x; method
init), instance ``thing`` of it (x = 3; method doit), export 0 = thing, export 1 = proc,
a local procedure that proc calls, and an orphan procedure nothing calls.
"""

from __future__ import annotations

import struct
from pathlib import Path

from cleanroom.kinds.sci import FORMATS, OPS

SELECTORS = ["species", "superClass", "-info-", "name", "init", "doit", "x", "new"]
KERNELS = ["Load", "Animate", "DrawPic"]
STRINGS = ["Obj", "thing", "hello"]
# Labels, then instructions. "@name" operands are absolute addresses made relative here.
PROGRAM = [
    "proc",
    ("pushi", [4], 1),
    ("push0", [], 0),
    ("lofsa", ["@thing"], 0),
    ("send", [4], 0),
    ("push0", [], 0),
    ("callk", [1, 0], 1),
    ("push0", [], 0),
    ("call", ["local", 0], 0),
    ("ret", [], 0),
    "local",
    ("ldi", [5], 1),
    ("ret", [], 0),
    "init",
    ("pushi", [6], 1),
    ("push1", [], 0),
    ("pushi", [9], 1),
    ("self", [6], 0),
    ("ret", [], 0),
    "doit",
    ("pushi", [4], 1),
    ("push0", [], 0),
    ("super", [0, 4], 1),
    ("lofss", ["@hello"], 0),
    ("toss", [], 0),
    ("pToa", [8], 1),
    ("ret", [], 0),
    "orphan",
    ("ldi", [1], 1),
    ("ret", [], 0),
]


def asm(insns: list[tuple], at: int = 0, labels: dict | None = None) -> bytes:
    """Bytes for ``(mnemonic, operands, small)``; a str operand is a label or ``@address``
    and becomes relative to the next instruction (code is laid out from ``at``)."""
    out, labels = bytearray(), labels or {}
    for name, args, small in insns:
        op = OPS.index(name)
        fmt = FORMATS.get(op, "")
        size = 1 + sum(1 if f == "b" or small else 2 for f in fmt)
        nxt = at + len(out) + size
        out.append(op << 1 | small)
        for f, v in zip(fmt, args, strict=True):
            if isinstance(v, str):
                v = labels.get(v.lstrip("@"), 0) - nxt
            out += bytes([v & 0xFF]) if f == "b" or small else struct.pack("<H", v & 0xFFFF)
    return bytes(out)


def _code(at: int, labels: dict) -> tuple[bytes, dict]:
    """Assemble PROGRAM from ``at``; returns the bytes and every label's offset."""
    pos, out, found = at, bytearray(), {}
    for item in PROGRAM:
        if isinstance(item, str):
            found[item] = pos
            continue
        raw = asm([item], pos, labels)
        out += raw
        pos += len(raw)
    return bytes(out), found


def _block(typ: int, body: bytes) -> bytes:
    return struct.pack("<HH", typ, len(body) + 4) + body


def _record(values: list[int], props: list[int], methods: list[tuple[int, int]]) -> bytes:
    """An object or class body: magic, locals pointer, method area pointer (relative to the
    values), count, values, class property selectors, then count, ids, 0, offsets."""
    n = len(values)
    area = 2 * n + 2 * len(props) + 2  # past values, props and the method count
    head = struct.pack("<4H", 0x1234, 0, area, n)
    tail = [len(methods), *[s for s, _ in methods], 0, *[o for _, o in methods]]
    return head + struct.pack(f"<{n + len(props) + len(tail)}H", *values, *props, *tail)


def script0() -> bytes:
    """Lay the script out twice: once to size every block, once with real addresses."""
    labels: dict = {}
    for _ in range(2):
        exports = _block(7, struct.pack("<3H", 2, labels.get("thing", 0), labels.get("proc", 0)))
        code_at = len(exports) + 4
        code, found = _code(code_at, labels)
        code_block = _block(2, code)
        cls_at = len(exports) + len(code_block)
        strings_body = b"".join(s.encode() + b"\0" for s in STRINGS)
        name = {s: 0 for s in STRINGS}
        # values: species, superClass, -info-, name, x
        cls = _record(
            [0, 0xFFFF, 0x8000, labels.get("s:Obj", 0), 0], [0, 1, 2, 3, 6], [(4, found["init"])]
        )
        cls_block = _block(6, cls)
        obj_at = cls_at + len(cls_block)
        obj = _record([0, 0, 0, labels.get("s:thing", 0), 3], [], [(5, found["doit"])])
        obj_block = _block(1, obj)
        str_at = obj_at + len(obj_block) + 4
        pos = str_at
        for s in STRINGS:
            name[s] = pos
            pos += len(s) + 1
        locals_block = _block(10, struct.pack("<2H", 7, 8))
        labels = {
            **found,
            "Obj": cls_at + 12,
            "thing": obj_at + 12,
            "hello": name["hello"],
            "s:Obj": name["Obj"],
            "s:thing": name["thing"],
        }
    body = exports + code_block + cls_block + obj_block + _block(5, strings_body) + locals_block
    return body + b"\0\0"


def names_sci0(names: list[str]) -> bytes:
    """Vocab 997 (and SCI0 999): count less one, offsets, then length-prefixed names."""
    offs, blob, at = [], b"", 2 + 2 * len(names)
    for n in names:
        offs.append(at + len(blob))
        blob += struct.pack("<H", len(n)) + n.encode()
    return struct.pack(f"<{len(names) + 1}H", len(names) - 1, *offs) + blob


def lzw_literals(data: bytes) -> bytes:
    """SCI0 method 1: every byte a literal code, LSB first, widths tracked as the decoder does."""
    acc = nbits = 0
    out = bytearray()
    width, end, cur = 9, 0x1FF, 0x102

    def emit(code: int) -> None:
        nonlocal acc, nbits
        acc |= code << nbits
        nbits += width
        while nbits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            nbits -= 8

    for b in data:
        emit(b)
        if cur > end and width < 12:
            width, end = width + 1, (end << 1) + 1
        if cur <= end:
            cur += 1
    emit(0x101)
    if nbits:
        out.append(acc & 0xFF)
    return bytes(out)


class _Msb:
    def __init__(self) -> None:
        self.bits: list[int] = []

    def put(self, value: int, width: int) -> None:
        self.bits.extend(value >> (width - 1 - i) & 1 for i in range(width))

    def bytes(self) -> bytes:
        bits = self.bits + [0] * (-len(self.bits) % 8)
        return bytes(int("".join(map(str, bits[i : i + 8])), 2) for i in range(0, len(bits), 8))


def huffman_literals(data: bytes) -> bytes:
    """Two nodes: bit 0 reaches the leaf for byte 0; bit 1 takes the zero right step, an
    8-bit escape. The terminator is escaped 0, which the encoder never writes."""
    w = _Msb()
    for b in data:
        w.put(int(b != 0), 1)
        if b:
            w.put(b, 8)
    return bytes([2, 0]) + bytes([0, 0x10, 0, 0]) + w.bytes()


def lzw1_literals(data: bytes) -> bytes:
    """SCI1 method 2 (COMP3): literal codes MSB first, widths tracked as the decoder does."""
    w, width, end, cur = _Msb(), 9, 0x1FF, 0x102
    for i, b in enumerate(data):
        w.put(b, width)
        if i and cur <= end:
            cur += 1
            if cur == end and width < 12:
                width, end = width + 1, (end << 1) + 1
    w.put(0x101, width)
    return w.bytes()


ENCODERS = {
    "SCI0": {1: lzw_literals, 2: huffman_literals},
    "SCI1-early": {1: huffman_literals, 2: lzw1_literals},
}


def resources() -> dict[tuple[int, int], bytes]:
    return {
        (2, 0): script0(),
        (6, 996): struct.pack("<2H", 0, 0),
        (6, 997): names_sci0(SELECTORS),
        (6, 999): b"\0".join(k.encode() for k in KERNELS) + b"\0",
    }


def build(root: Path, method: int = 0, version: str = "SCI0", dupe: bool = False) -> Path:
    """Write the game; ``dupe`` repeats the script's map entry, as two-disk games do."""
    root.mkdir(parents=True, exist_ok=True)
    vol, entries = bytearray(), []
    for (typ, num), data in resources().items():
        packed = ENCODERS[version][method](data) if method else data
        entries.append((typ << 11 | num, len(vol)))
        vol += struct.pack("<4H", typ << 11 | num, len(packed) + 4, len(data), method) + packed
    if dupe:
        entries.append(entries[0])
    rows = b"".join(struct.pack("<HI", rid, 0 << 26 | off) for rid, off in entries)
    (root / "resource.map").write_bytes(rows + b"\xff" * 6)
    (root / "resource.000").write_bytes(bytes(vol))
    return root
