"""Sierra SCI games: resource.map and its volumes, decompression, scripts and bytecode.

A target is the game directory or its ``resource.map``. SCI0 and SCI1-early share
the 6-byte map entry; they differ in what compression methods 1 and 2 mean, which
open settles by decoding a few resources both ways. Patch files (``script.100``)
override the map, as the interpreter does. Scripts use the SCI0 block format.

Every script is its own address space. A function's address packs both halves,
``script << 16 | offset``, so ``0x64002e`` is script 100 offset 0x2e; refs also
take ``100:0x2e``, a name (``Obj::selector``, ``proc_100_2``, ``localproc_100_00b4``),
``script:100``, ``view:100`` (any resource), ``kernel:Animate`` or ``selector:init``.
"""

from __future__ import annotations

import builtins
import hashlib
import os
import re
import struct
from dataclasses import dataclass, field
from typing import Any

from cleanroom.evidence import Finding
from cleanroom.kinds.native import _match
from cleanroom.target import Fail, Target, parse_ref

LIST_WHAT = ("resources", "scripts", "objects", "functions", "strings", "kernels", "selectors")
SHOW_VIEWS = ("auto", "info", "asm", "object", "hex")
DIFF_KEYS = {
    "resources": "id",
    "scripts": "script",
    "objects": "name",
    "functions": "name",
    "strings": "value",
    "kernels": "name",
    "selectors": "name",
}
DIFF_IGNORE = {"address", "offset", "size", "volume"}
TYPES = (
    "view pic script text sound memory vocab font cursor patch bitmap palette "
    "cdaudio audio sync message map heap"
).split()
PATCH = re.compile(rf"({'|'.join(TYPES[:12])})\.(\d{{3}})", re.I)
RES_REF = re.compile(rf"({'|'.join(TYPES)}):(\d+)")
MAP, END = "resource.map", b"\xff" * 6
VOCAB_SELECTORS, VOCAB_KERNELS, VOCAB_CLASSES = 997, 999, 996
MAGIC = 0x1234  # every object and class record starts with it
OBJECT, CODE, STRINGS, CLASS, EXPORTS, LOCALS = 1, 2, 5, 6, 7, 10
SCRIPT = TYPES.index("script")
HINT = "try list functions --match"
AUTO_ASM_LINES, HEX_VIEW, FUZZY_MIN, PROBES = 40, 256, 3, 4
HEX_KEYS = ("address", "ref", "at")
UNRESOLVED = "a send to an object held in a variable names only its selector (selector:...)"


def _parse_map(data: bytes) -> list[tuple[int, int, int, int]] | None:
    """``(type, number, volume, offset)`` per SCI0-style entry, or None for another format."""
    if len(data) < 6 or len(data) % 6 or data[-6:] != END:
        return None
    out = []
    for i in range(0, len(data) - 6, 6):
        rid, loc = struct.unpack_from("<HI", data, i)
        if rid >> 11 >= len(TYPES):
            return None
        out.append((rid >> 11, rid & 0x7FF, loc >> 26, loc & 0x3FFFFFF))
    return out


def _is_later_map(data: bytes) -> bool:
    """SCI1-middle and later maps open with a type table: ``type|0x80, u16`` rows, 0xFF last."""
    return len(data) >= 6 and 0x80 <= data[0] <= 0x91 and b"\xff" in data[:64:3]


def _root(path: str) -> str | None:
    if os.path.isdir(path):
        return path if os.path.isfile(os.path.join(path, MAP)) else None
    return os.path.dirname(path) if os.path.basename(path).lower() == MAP else None


def detect(path: str, head: bytes) -> bool:
    """A directory holding a resource.map, or that file itself, whose layout is SCI."""
    root = _root(path)
    if root is None:
        return False
    try:
        with builtins.open(os.path.join(root, MAP), "rb") as f:
            data = f.read(1 << 20)
    except OSError:
        return False
    return _parse_map(data) is not None or _is_later_map(data)


class _Bits:
    """A bit reader over ``src``: LSB first for SCI0 LZW, MSB first for Huffman and LZW1."""

    def __init__(self, src: bytes, msb: bool):
        self.src, self.msb, self.pos, self.acc, self.n = src, msb, 0, 0, 0

    def get(self, width: int) -> int:
        while self.n < width:
            if self.pos >= len(self.src):
                raise Fail("failed", "compressed data ends early")
            byte, self.pos = self.src[self.pos], self.pos + 1
            self.acc = (self.acc << 8 | byte) if self.msb else (self.acc | byte << self.n)
            self.n += 8
        self.n -= width
        if self.msb:
            v = self.acc >> self.n
            self.acc &= (1 << self.n) - 1
            return v
        v = self.acc & ((1 << width) - 1)
        self.acc >>= width
        return v


def _lzw(src: bytes, size: int) -> bytes:
    """SCI0 method 1: LZW, 9 to 12 bit codes LSB first; a code copies an earlier run plus one."""
    bits, out = _Bits(src, False), bytearray()
    width, end, cur, last = 9, 0x1FF, 0x102, 0
    starts, lens = [0] * 4096, [0] * 4096
    while len(out) < size:
        tok = bits.get(width)
        if tok == 0x101:
            break
        if tok == 0x100:
            width, end, cur = 9, 0x1FF, 0x102
            continue
        if tok > 0xFF:
            if tok >= cur:
                raise Fail("failed", f"LZW code 0x{tok:x} before it is defined")
            last, start = lens[tok] + 1, starts[tok]
            for i in range(min(last, size - len(out))):
                out.append(out[start + i])
        else:
            out.append(tok)
            last = 1
        if cur > end and width < 12:
            width, end = width + 1, (end << 1) + 1
        if cur <= end:
            starts[cur], lens[cur], cur = len(out) - last, last, cur + 1
    return bytes(out)


def _huffman(src: bytes, size: int) -> bytes:
    """SCI0 method 2, SCI1 method 1: a node table, then MSB-first paths; 0 right means literal."""
    count, term = src[0], src[1] | 0x100
    nodes, bits, out = src[2 : 2 + 2 * count], _Bits(src[2 + 2 * count :], True), bytearray()
    while len(out) < size:
        i = 0
        while nodes[i + 1]:
            if bits.get(1):
                step = nodes[i + 1] & 0x0F
                if not step:
                    c = bits.get(8) | 0x100
                    break
            else:
                step = nodes[i + 1] >> 4
            i += step << 1
        else:
            c = nodes[i]
        if c == term:
            break
        out.append(c & 0xFF)
    return bytes(out)


def _lzw1(src: bytes, size: int) -> bytes:
    """SCI1 method 2 (COMP3): LZW, codes MSB first, each a (byte, previous code) link."""
    bits, out = _Bits(src, True), bytearray()
    width, end, cur, last, first, tail = 9, 0x1FF, 0x102, 0, True, 0
    data, link = [0] * 0x1004, [0] * 0x1004
    while len(out) < size:
        code = bits.get(width)
        if code == 0x101:
            break
        if first:
            out.append(code & 0xFF)
            last, tail, first = code, code & 0xFF, False
            continue
        if code == 0x100:
            width, end, cur, first = 9, 0x1FF, 0x102, True
            continue
        tok, run = code, []
        if tok >= cur:
            tok = last
            run.append(tail)
        while 0xFF < tok < 0x1004:
            run.append(data[tok])
            tok = link[tok]
        tail = tok & 0xFF
        run.append(tail)
        out.extend(reversed(run))
        if cur <= end:
            data[cur], link[cur], cur = tail, last, cur + 1
            if cur == end and width < 12:
                width, end = width + 1, (end << 1) + 1
        last = code
    return bytes(out[:size])


# Compression method -> decoder, per generation; methods 3 and 4 (SCI1 view, pic) are not here.
METHODS = {"SCI0": {1: _lzw, 2: _huffman}, "SCI1-early": {1: _huffman, 2: _lzw1}}


@dataclass
class Handle:
    """One opened game: where each resource lives, its generation and lazily built tables."""

    root: str
    version: str
    where: dict[tuple[int, int], tuple]  # (type, number) -> (volume, offset) or (path,)
    content: str
    cache: dict[str, Any] = field(default_factory=dict)
    unknowns: list[str] = field(default_factory=list)


def _read_at(root: str, volume: int, offset: int) -> tuple[int, int, int, bytes]:
    """``(method, packed, unpacked, raw)`` for the entry at ``offset`` in resource.<volume>."""
    with builtins.open(os.path.join(root, f"resource.{volume:03d}"), "rb") as f:
        f.seek(offset)
        head = f.read(8)
        if len(head) < 8:
            raise Fail("failed", f"resource.{volume:03d} ends before offset 0x{offset:x}")
        _, packed, size, method = struct.unpack("<HHHH", head)
        return method, packed - 4, size, f.read(packed - 4)


def _decode(version: str, method: int, raw: bytes, size: int) -> bytes:
    if method == 0:
        return raw[:size]
    if method not in METHODS[version]:
        raise Fail("unsupported", f"{version} compression method {method} is not decoded")
    return METHODS[version][method](raw, size)


def _generation(root: str, entries: list[tuple]) -> str:
    """SCI0 when the first PROBES compressed entries decode to their size under its methods."""
    probes = []
    for _, _, vol, off in entries:
        method, _, size, raw = _read_at(root, vol, off)
        if method in (1, 2):
            probes.append((method, raw, size))
        if len(probes) == PROBES:
            break
    for version in METHODS:
        try:
            if all(len(_decode(version, m, raw, n)) == n for m, raw, n in probes):
                return version
        except (Fail, IndexError):
            continue
    raise Fail("unsupported", "compressed resources decode as neither SCI0 nor SCI1-early")


def _content(root: str, names: list[str]) -> str:
    """Digest of the map, the volumes and the patch files: a directory target's own digest
    covers names and sizes only, so a byte edit at the same size would go unseen."""
    digest = hashlib.sha256()
    for name in names:
        with builtins.open(os.path.join(root, name), "rb") as f:
            while chunk := f.read(1 << 20):
                digest.update(name.encode() + b"\0" + chunk)
    return digest.hexdigest()


def open(target: Target, engine: str | None = None, arch: str | None = None) -> Handle:
    """Bind a game directory; SCI1-middle and later maps are recognised but not read yet."""
    if engine not in (None, "builtin"):
        raise Fail("unsupported", f"SCI targets have one engine, builtin, not {engine!r}")
    root = _root(target.path) or target.path
    with builtins.open(os.path.join(root, MAP), "rb") as f:
        entries = _parse_map(f.read())
    if entries is None:
        why = "SCI1-middle and later maps (type-table header) are not read yet"
        raise Fail("unsupported", why, "SCI0 and SCI1-early games are")
    where: dict[tuple[int, int], tuple] = {}
    for typ, num, vol, off in entries:  # a resource on both disks: the first copy wins
        where.setdefault((typ, num), (vol, off))
    names = [MAP, *sorted({f"resource.{v:03d}" for v, _ in where.values()})]
    for name in sorted(os.listdir(root)):
        if m := PATCH.fullmatch(name):
            where[(TYPES.index(m[1].lower()), int(m[2]))] = (os.path.join(root, name),)
            names.append(name)
    h = Handle(root, _generation(root, entries), where, _content(root, names))
    h.cache["dupes"] = len(entries) - len({(t, n) for t, n, _, _ in entries})
    return h


def close(handle: Handle) -> None:
    """Nothing to release: volumes are read per resource and closed again."""


def resource(h: Handle, typ: int | str, number: int) -> bytes:
    """The decoded bytes of one resource; a library entry point for SCI-Recomp."""
    typ = TYPES.index(typ) if isinstance(typ, str) else typ
    key = ("res", typ, number)
    if key not in h.cache:
        loc = h.where.get((typ, number))
        if loc is None:
            raise Fail("not_found", f"no {TYPES[typ]}.{number:03d} in this game", "list resources")
        if len(loc) == 1:  # a patch file: type byte, header length, then the data
            with builtins.open(loc[0], "rb") as f:
                raw = f.read()
            skip = raw[1] if raw[1] < 0x80 else {0: 24, 1: 2, 4: 8}.get(raw[1] & 0x7F, 0)
            h.cache[key] = raw[2 + skip :]
        else:
            method, _, size, raw = _read_at(h.root, *loc)
            data = _decode(h.version, method, raw, size)
            if len(data) != size:
                raise Fail("failed", f"{TYPES[typ]}.{number:03d}: {len(data)} of {size} bytes")
            h.cache[key] = data
    return h.cache[key]


def _names(data: bytes) -> list[str]:
    """Vocab 997 (and SCI0's 999): a count less one, offsets, then length-prefixed names.
    SCI1's 999 is NUL-separated names instead."""
    count = struct.unpack_from("<H", data)[0] + 1
    if 2 + 2 * count > len(data):
        return [s.decode("latin-1") for s in data.split(b"\0")[:-1]]
    out = []
    for i in range(count):
        off = struct.unpack_from("<H", data, 2 + 2 * i)[0]
        if off + 2 > len(data):
            return [s.decode("latin-1") for s in data.split(b"\0")[:-1]]
        n = struct.unpack_from("<H", data, off)[0]
        out.append(data[off + 2 : off + 2 + n].decode("latin-1"))
    return out


def _vocab(h: Handle, number: int) -> list:
    key = ("vocab", number)
    if key not in h.cache:
        try:
            data = resource(h, "vocab", number)
        except Fail:
            h.unknowns.append(f"vocab.{number} is missing: its names show as numbers")
            data = b""
        if number == VOCAB_CLASSES:  # 4 bytes per class: a runtime slot, then the script
            h.cache[key] = [
                struct.unpack_from("<H", data, i + 2)[0] for i in range(0, len(data), 4)
            ]
        else:
            h.cache[key] = _names(data) if data else []
    return h.cache[key]


def selector(h: Handle, n: int) -> str:
    names = _vocab(h, VOCAB_SELECTORS)
    return names[n] if 0 <= n < len(names) else f"sel_{n}"


def kernel(h: Handle, n: int) -> str:
    """The kernel's name; vocab 999 can list fewer than the interpreter has (Jones: 117)."""
    names = _vocab(h, VOCAB_KERNELS)
    if 0 <= n < len(names):
        return names[n]
    why = f"kernel {n} is past the {len(names)} names in vocab.999; it shows as kernel_{n}"
    if why not in h.unknowns:
        h.unknowns.append(why)
    return f"kernel_{n}"


def info(handle: Handle) -> dict:
    scripts = sorted(n for t, n in handle.where if t == SCRIPT)
    return {
        "engine": "builtin-sci",
        "format": handle.version,
        "arch": "sci-vm",
        "resources": len(handle.where),
        "scripts": len(scripts),
        "duplicates": handle.cache["dupes"],
        "patches": sum(len(v) == 1 for v in handle.where.values()),
        "content_sha256": handle.content,
        "views": [*SHOW_VIEWS],
    }


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0] if 0 <= off <= len(data) - 2 else 0


def _cstr(data: bytes, off: int) -> str:
    end = data.find(b"\0", off)
    return data[off : end if end >= 0 else len(data)].decode("latin-1")


def _object(data: bytes, start: int, typ: int) -> dict:
    """One object or class record. Its address is the block start + 12: the property values
    begin there, the method area pointer is relative to it, and exports point at it."""
    at, nvars = start + 12, _u16(data, start + 10)
    if _u16(data, start + 4) != MAGIC:
        raise Fail("failed", f"no object magic at 0x{start:x}")
    values = [_u16(data, at + 2 * i) for i in range(nvars)]
    props = [_u16(data, at + 2 * (nvars + i)) for i in range(nvars)] if typ == CLASS else []
    area = at + _u16(data, start + 8)
    count = _u16(data, area - 2)
    sels = [_u16(data, area + 2 * i) for i in range(count)]
    offs = [_u16(data, area + 2 * (count + 1 + i)) for i in range(count)]
    name = _cstr(data, values[3]) if nvars > 3 and values[3] < len(data) else ""
    return {
        "address": at,
        "name": name or f"obj@{at:04x}",
        "class": typ == CLASS,
        "species": values[0] if values else 0,
        "super": values[1] if nvars > 1 else 0xFFFF,
        "values": values,
        "props": props,
        "methods": dict(zip(sels, offs, strict=True)),
    }


def script(h: Handle, number: int) -> dict:
    """A parsed script: objects, exports, code ranges, strings and locals, with offsets."""
    key = ("script", number)
    if key in h.cache:
        return h.cache[key]
    data = resource(h, "script", number)
    out: dict = {"number": number, "size": len(data), "data": data, "objects": [], "code": []}
    out.update(exports=[], strings=[], locals=[], blocks=[])
    pos = 0
    while pos + 4 <= len(data) and (typ := _u16(data, pos)):
        size = _u16(data, pos + 2)
        if size < 4 or pos + size > len(data):
            h.unknowns.append(f"script {number}: block {typ} at 0x{pos:x} overruns; parse stops")
            break
        out["blocks"].append({"type": typ, "offset": pos, "size": size})
        body = range(pos + 4, pos + size)
        if typ in (OBJECT, CLASS):
            out["objects"].append(_object(data, pos, typ))
        elif typ == CODE:
            out["code"].append((body.start, body.stop))
        elif typ == EXPORTS:
            out["exports"] = [_u16(data, pos + 6 + 2 * i) for i in range(_u16(data, pos + 4))]
        elif typ == STRINGS:
            at = body.start
            for raw in data[body.start : body.stop].split(b"\0"):
                if raw:
                    out["strings"].append((at, raw.decode("latin-1")))
                at += len(raw) + 1
        elif typ == LOCALS:
            out["locals"] = [_u16(data, i) for i in range(body.start, body.stop - 1, 2)]
        pos += size
    h.cache[key] = out
    return out


# The 64 base opcodes, then load/store/inc/dec over global, local, temp and param variables.
# An opcode byte is op << 1 | small: small operands are one byte, otherwise two.
OPS = (
    "bnot add sub mul div mod shr shl xor and or neg not eq? ne? gt? ge? lt? le? ugt? uge? "
    "ult? ule? bt bnt jmp ldi push pushi toss dup link call callk callb calle ret send - - "
    "class - self super &rest lea selfID - pprev pToa aTop pTos sTop ipToa dpToa ipTos dpTos "
    "lofsa lofss push0 push1 push2 pushSelf -"
).split() + [
    "ls+-"[op >> 4 & 3] + "as"[op >> 2 & 1] + "gltp"[op & 3] + "i" * (op >> 3 & 1)
    for op in range(64)
]
# Operands: v unsigned and s signed (sized by the small bit), r a signed relative, b one byte.
# pushi is signed: the compiler writes -3 as the byte 0xFD (Jones script 107).
FORMATS = {
    **dict.fromkeys(range(0x31, 0x39), "v"),
    **dict.fromkeys(range(0x40, 0x80), "v"),
    0x17: "r", 0x18: "r", 0x19: "r", 0x1A: "s", 0x1C: "s", 0x1F: "v", 0x20: "rb", 0x21: "vb",
    0x22: "vb", 0x23: "vvb", 0x25: "b", 0x28: "v", 0x2A: "b", 0x2B: "vb", 0x2C: "v",
    0x2D: "sv", 0x39: "r", 0x3A: "r",
}  # fmt: skip
PROP_OPS = {"pToa", "aTop", "pTos", "sTop", "ipToa", "dpToa", "ipTos", "dpTos"}
BINARY = set(OPS[1:11]) | set(OPS[13:23])  # pop one, combine with acc
PUSHES = {"push0": 0, "push1": 1, "push2": 2}


def _insn(data: bytes, off: int, end: int) -> tuple[str, list[int], int] | None:
    """``(mnemonic, operands, size)`` at ``off``, or None for an unused opcode or a cut one."""
    op, small = data[off] >> 1, data[off] & 1
    if OPS[op] == "-":
        return None
    args, p = [], off + 1
    for f in FORMATS.get(op, ""):
        wide = f != "b" and not small
        if p + 1 + wide > end:
            return None
        v = _u16(data, p) if wide else data[p]
        p += 1 + wide
        if f in "sr" and v >= (0x8000 if wide else 0x80):
            v -= 0x10000 if wide else 0x100
        args.append(v)
    return OPS[op], args, p - off


def _gap(insns: dict, data: bytes, start: int, end: int) -> int | None:
    """The first offset in a code block that no instruction covers, past zero padding."""
    off = start
    while off < end and off in insns:
        off += insns[off][2]
    return off if off < end and data[off:end].strip(b"\0") else None


def _decoded(h: Handle, n: int) -> tuple[dict, dict]:
    """Instructions by offset and entry points by offset (name, kind, owning object).

    Entries are the methods, the exports that point into code and every ``call`` target.
    Each is decoded straight on to a ``ret`` that no earlier branch jumps past, the next
    entry or the end of its block; code left over after that is an unreferenced procedure.
    """
    key = ("decoded", n)
    if key in h.cache:
        return h.cache[key]
    s = script(h, n)
    data, objs = s["data"], {o["address"] for o in s["objects"]}
    entries: dict[int, tuple] = {}
    for o in s["objects"]:
        for sel, off in o["methods"].items():
            entries.setdefault(off, (f"{o['name']}::{selector(h, sel)}", "method", o))
    for i, off in enumerate(s["exports"]):
        if off and off not in objs:
            entries.setdefault(off, (f"proc_{n}_{i}", "procedure", None))
    insns: dict[int, tuple] = {}
    work = sorted(entries)
    while work:
        start = off = work.pop()
        block = next(((a, b) for a, b in s["code"] if a <= start < b), None)
        if block is None:
            h.unknowns.append(f"script {n}: entry 0x{start:04x} is outside every code block")
            entries.pop(start, None)
            continue
        reach = start
        while off < block[1] and off not in insns and (off == start or off not in entries):
            got = _insn(data, off, block[1])
            if got is None:
                h.unknowns.append(f"script {n}: undecodable byte 0x{data[off]:02x} at 0x{off:04x}")
                break
            insns[off] = got
            to = off + got[2] + (got[1][0] if got[1] else 0)
            if got[0] == "call" and to not in entries:
                entries[to] = (f"localproc_{n}_{to:04x}", "local", None)
                work.append(to)
            reach = max(reach, to) if got[0] in ("bt", "bnt", "jmp") else reach
            off += got[2]
            if got[0] == "ret" and off > reach:  # no branch lands past it: the function ends
                break
        if not work:  # the compiler kept procedures nothing calls: decode them too
            gaps = (_gap(insns, data, a, b) for a, b in s["code"])
            work = [g for g in gaps if g is not None and g not in entries]
            for g in work:
                entries[g] = (f"localproc_{n}_{g:04x}", "unreferenced", None)
    h.cache[key] = insns, entries
    return insns, entries


def _class(h: Handle, number: int) -> tuple[int, dict] | None:
    """``(script, class object)`` for a class number, through vocab 996."""
    homes = _vocab(h, VOCAB_CLASSES)
    if not 0 <= number < len(homes) or (SCRIPT, homes[number]) not in h.where:
        return None
    for o in script(h, homes[number])["objects"]:
        if o["class"] and o["species"] == number:
            return homes[number], o
    return None


def _props(h: Handle, obj: dict) -> list[int]:
    """Property selectors: a class lists its own, an instance takes its species' list."""
    if obj["class"]:
        return obj["props"]
    found = _class(h, obj["species"])
    return found[1]["props"] if found else []


def _lookup(h: Handle, n: int, obj: dict, sel: int) -> tuple[str, int, str] | None:
    """What ``sel`` reaches on ``obj``: ``("method", address, defining name)``,
    ``("prop", 0, owner name)``, or None when the chain leaves the game."""
    if sel in _props(h, obj):
        return "prop", 0, obj["name"]
    for _ in range(64):  # superclass chains are short; a cycle would be corrupt data
        if sel in obj["methods"]:
            return "method", n << 16 | obj["methods"][sel], obj["name"]
        found = _class(h, obj["super"]) if obj["super"] != 0xFFFF else None
        if found is None:
            return None
        n, obj = found
    return None


def _frames(frame: list) -> list[tuple[int, int]] | None:
    """``(selector, argc)`` pairs from one send's stack frame, or None when it does not add up."""
    out, i = [], 0
    while i < len(frame):
        if i + 1 >= len(frame) or None in (frame[i], frame[i + 1]) or frame[i + 1] < 0:
            return None
        out.append((frame[i], frame[i + 1]))
        i += 2 + frame[i + 1]
    return out if i == len(frame) else None


def _target(h: Handle, n: int, off: int) -> tuple[str, str]:
    """``(type, label)`` for what a lofsa or lofss offset names in script ``n``."""
    s = script(h, n)
    for o in s["objects"]:
        if o["address"] == off:
            return "data", o["name"]
    for at, text in s["strings"]:
        if at <= off < at + len(text) + 1:
            return "string", repr(text[off - at :][:40])
    return "data", f"0x{off:04x}"


def _body(h: Handle, n: int, start: int):
    """``(offset, mnemonic, operands, size)`` from an entry to the next one."""
    insns, entries = _decoded(h, n)
    off = start
    while off in insns and (off == start or off not in entries):
        yield off, *insns[off]
        off += insns[off][2]


def _export(h: Handle, n: int, i: int) -> tuple[int | str, str]:
    """The ref and name of export ``i`` of script ``n``; a missing script stays a name."""
    try:
        off = script(h, n)["exports"][i]
    except (Fail, IndexError):
        return f"proc_{n}_{i}", f"proc_{n}_{i}"
    return n << 16 | off, _decoded(h, n)[1].get(off, (f"proc_{n}_{i}",))[0]


def _send(h: Handle, n: int, recv: tuple | None, frame: list, at: int, edges: list) -> str:
    """Name each message in a send frame; a resolved method is a call edge, a property data."""
    pairs = _frames(frame)
    if pairs is None:
        return "?"
    notes = []
    for sel, argc in pairs:
        name, hit = selector(h, sel), _lookup(h, *recv, sel) if recv else None
        if hit and hit[0] == "method":
            edges.append({"ref": hit[1], "name": f"{hit[2]}::{name}", "type": "call", "at": at})
        else:
            typ = "data" if hit else "call"
            edges.append({"ref": f"selector:{name}", "name": name, "type": typ, "at": at})
        notes.append(f"{hit[2] + '::' if hit else ''}{name}({argc})")
    return ", ".join(notes)


def _flow(h: Handle, n: int, start: int) -> tuple[list[str], list[dict]]:
    """Asm lines and outgoing edges for one function, from a symbolic stack of constants:
    a send frame resolves when every selector and argc in it was pushed as a constant."""
    key = ("flow", n, start)
    if key in h.cache:
        return h.cache[key]
    me = _decoded(h, n)[1][start][2]
    me_ref = (n, me) if me else None
    lines, edges, stack, acc = [], [], [], None
    for off, op, args, size in _body(h, n, start):
        nxt, note, ops = off + size, "", [str(a) for a in args]
        at = n << 16 | off
        if op in ("bt", "bnt", "jmp"):
            ops = [f"0x{nxt + args[0]:04x}"]
        elif op == "call":
            to = nxt + args[0]
            note, ops[0] = _decoded(h, n)[1][to][0], f"0x{to:04x}"
            edges.append({"ref": n << 16 | to, "name": note, "type": "call", "at": at})
        elif op in ("callb", "calle"):
            ref, note = _export(h, *([0, *args] if op == "callb" else args)[:2])
            edges.append({"ref": ref, "name": note, "type": "call", "at": at})
        elif op == "callk":
            note = kernel(h, args[0])
            edges.append({"ref": f"kernel:{note}", "name": note, "type": "import", "at": at})
        elif op in ("send", "self", "super"):
            count = args[-1] // 2
            frame = stack[-count:] if 0 < count <= len(stack) else [None]
            recv = {"send": acc, "self": me_ref, "super": _class(h, args[0])}[op]
            note = _send(h, n, recv if isinstance(recv, tuple) else None, frame, at, edges)
        elif op in ("lofsa", "lofss"):
            typ, note = _target(h, n, nxt + args[0])
            ops = [f"0x{nxt + args[0]:04x}"]
            edges.append({"ref": n << 16 | nxt + args[0], "name": note, "type": typ, "at": at})
        elif op == "class":
            found = _class(h, args[0])
            note = found[1]["name"] if found else ""
        elif op in PROP_OPS and me:
            props = _props(h, me)
            note = selector(h, props[args[0] // 2]) if args[0] // 2 < len(props) else ""
        lines.append(f"0x{off:04x}: {op} {', '.join(ops)}".rstrip() + (f"  ; {note}" * bool(note)))
        stack, acc = _effect(h, n, op, args, stack, acc, me_ref, nxt)
    h.cache[key] = lines, edges
    return lines, edges


VAR_OPS = set(OPS[64:])
CALLS = {"call": 1, "callk": 1, "callb": 1, "calle": 1, "send": 0, "self": 0, "super": 0}
KEEP_ACC = set(
    "bt bnt jmp push pushi push0 push1 push2 pushSelf toss dup link aTop sTop &rest pTos "
    "ipTos dpTos lofss pprev".split()
)


def _effect(h: Handle, n: int, op: str, args: list, stack: list, acc: Any, me, nxt: int):
    """The tracked stack (constants or None) and acc (constant, ``(script, object)`` or None)
    after one instruction. Only what send frames need is modelled; the rest is None."""
    pops, push = 0, []
    if op in CALLS:
        pops = args[-1] // 2 + CALLS[op]
    elif op in BINARY or op in ("toss", "sTop"):
        pops = 1
    elif op in VAR_OPS:
        load, to_stack = op[0] in "l+-", op[1] == "s"
        push = [None] if load and to_stack else []
        pops = int(op[0] == "s" and (to_stack or op.endswith("i")))
    elif op == "pushi" or op in PUSHES:
        push = [args[0] if op == "pushi" else PUSHES[op]]
    elif op == "push":
        push = [acc if isinstance(acc, int) else None]
    elif op == "dup":
        push = stack[-1:] or [None]
    elif op == "link":
        push = [None] * args[0]
    elif op in ("pushSelf", "pprev", "lofss", "pTos", "ipTos", "dpTos"):
        push = [None]
    stack = stack[: max(0, len(stack) - pops)] + push
    if op == "ldi":
        return stack, args[0]
    if op == "lofsa":
        objs = [o for o in script(h, n)["objects"] if o["address"] == nxt + args[0]]
        return stack, (n, objs[0]) if objs else None
    if op == "class":
        return stack, _class(h, args[0])
    if op == "selfID":
        return stack, me
    keep = op in KEEP_ACC or (op in VAR_OPS and (op[1] == "s" or op[0] == "s"))
    return stack, acc if keep else None


def _scripts(h: Handle) -> builtins.list[int]:
    return sorted(n for t, n in h.where if t == SCRIPT)


def _functions(h: Handle) -> builtins.list[dict]:
    out = []
    for n in _scripts(h):
        insns, entries = _decoded(h, n)
        for off, (name, kind, _) in sorted(entries.items()):
            size = sum(i[3] for i in _body(h, n, off))
            item = {"name": name, "address": n << 16 | off, "script": n, "offset": off}
            out.append({**item, "size": size, "kind": kind})
    return out


def _objects(h: Handle) -> builtins.list[dict]:
    out = []
    for n in _scripts(h):
        for o in script(h, n)["objects"]:
            sup = _class(h, o["super"]) if o["super"] != 0xFFFF else None
            item = {"name": o["name"], "address": n << 16 | o["address"], "script": n}
            item.update(type="class" if o["class"] else "instance", methods=len(o["methods"]))
            out.append({**item, "super": sup[1]["name"] if sup else None})
    return out


def _resources(h: Handle) -> builtins.list[dict]:
    out = []
    for (t, n), loc in sorted(h.where.items()):
        where = {"patch": os.path.basename(loc[0])} if len(loc) == 1 else {"volume": loc[0]}
        out.append({"id": f"{TYPES[t]}:{n}", "type": TYPES[t], "number": n, **where})
    return out


def _script_rows(h: Handle) -> builtins.list[dict]:
    rows = []
    for n in _scripts(h):
        s = script(h, n)
        counts = {k: len(s[k]) for k in ("objects", "exports", "strings", "locals")}
        rows.append({"script": n, "size": s["size"], **counts})
    return rows


BUILDERS = {
    "resources": _resources,
    "scripts": _script_rows,
    "objects": _objects,
    "functions": _functions,
    "strings": lambda h: [
        {"address": n << 16 | at, "script": n, "value": text}
        for n in _scripts(h)
        for at, text in script(h, n)["strings"]
    ],
    "kernels": lambda h: [{"name": k, "number": i} for i, k in enumerate(_vocab(h, 999))],
    "selectors": lambda h: [{"name": k, "number": i} for i, k in enumerate(_vocab(h, 997))],
}


def _table(h: Handle, what: str) -> builtins.list[dict]:
    if what not in h.cache:
        h.cache[what] = BUILDERS[what](h)
    return h.cache[what]


def _public(item: dict) -> dict:
    return {
        k: f"0x{v:x}" if k in HEX_KEYS and isinstance(v, int) else v
        for k, v in item.items()
        if not k.startswith("_")
    }


def list(handle: Handle, what: str, match: str | None = None) -> builtins.list[dict] | Finding:
    """Inventory of ``what`` (see LIST_WHAT), optionally filtered by ``match``."""
    if what not in LIST_WHAT:
        raise Fail("bad_input", f"unknown what {what!r}", "one of " + ", ".join(LIST_WHAT))
    items = _match([_public(i) for i in _table(handle, what)], match)
    unknowns = tuple(dict.fromkeys(handle.unknowns))
    if unknowns and not isinstance(items, Finding):
        return Finding(items, "observed", unknowns)
    return items


def _hit(items: builtins.list[dict], value: str, what: str) -> dict | None:
    if len(items) > 1:
        names = ", ".join(f"{i['name']}@0x{i['address']:x}" for i in items[:12])
        raise Fail("ambiguous", f"{value!r} matches {len(items)} {what}", "candidates: " + names)
    return items[0] if items else None


def _resolve(h: Handle, ref: str) -> tuple[str, Any]:
    """``(kind, item)`` for a ref: a resource, kernel or selector by prefix; an address
    (function containing it, else an object at it); an exact function or object name;
    then a function name suffix or substring of FUZZY_MIN or more characters."""
    ref = ref.strip()
    if m := RES_REF.fullmatch(ref):
        return "resource", (TYPES.index(m[1]), int(m[2]))
    prefix, _, name = ref.partition(":")
    if prefix in ("kernel", "selector") and name:
        if name not in _vocab(h, VOCAB_KERNELS if prefix == "kernel" else VOCAB_SELECTORS):
            raise Fail("not_found", f"no {prefix} named {name!r}", f"list {prefix}s")
        return prefix, name
    parsed = parse_ref(ref)
    funcs, objs = _table(h, "functions"), _table(h, "objects")
    if parsed[0] == "addr":
        if parsed[2] is not None and not parsed[2].isdigit():
            raise Fail("bad_input", f"{ref!r}: the space before ':' is a script number")
        addr = int(parsed[2]) << 16 | parsed[1] if parsed[2] else parsed[1]
        inside = [f for f in funcs if f["address"] <= addr < f["address"] + max(f["size"], 1)]
        if f := _hit(inside, ref, "functions"):
            return "function", f
        if o := _hit([o for o in objs if o["address"] == addr], ref, "objects"):
            return "object", o
        raise Fail("not_found", f"{ref} is not inside a known function or at an object", HINT)
    if not ref:
        raise Fail("bad_input", "ref is empty")
    if f := _hit([f for f in funcs if f["name"] == ref], ref, "functions"):
        return "function", f
    if o := _hit([o for o in objs if o["name"] == ref], ref, "objects"):
        return "object", o
    if len(ref) >= FUZZY_MIN:
        fuzzy = [f for f in funcs if f["name"].endswith(ref)] or [
            f for f in funcs if ref in f["name"]
        ]
        if f := _hit(fuzzy, ref, "functions"):
            return "function", f
    raise Fail("not_found", f"no function or object named {ref!r}", HINT)


def _index(h: Handle) -> tuple[dict, dict]:
    """Edges out of each function and into each target, built over every function once."""
    if "index" not in h.cache:
        outs: dict = {}
        ins: dict = {}
        for f in _table(h, "functions"):
            outs[f["address"]] = edges = _flow(h, f["script"], f["offset"])[1]
            for e in edges:
                back = {"ref": f["address"], "name": f["name"], "type": e["type"], "at": e["at"]}
                ins.setdefault(e["ref"], []).append(back)
        h.cache["index"] = outs, ins
    return h.cache["index"]


def _object_view(h: Handle, n: int, o: dict) -> dict:
    """An object's properties by selector name and its methods by address."""
    props = _props(h, o)
    names = [
        selector(h, props[i]) if i < len(props) else f"prop_{i}" for i in range(len(o["values"]))
    ]
    sup = _class(h, o["super"]) if o["super"] != 0xFFFF else None
    head = {"name": o["name"], "address": f"0x{n << 16 | o['address']:x}", "script": n}
    head.update(type="class" if o["class"] else "instance", super=sup[1]["name"] if sup else None)
    methods = {selector(h, k): f"0x{n << 16 | v:x}" for k, v in o["methods"].items()}
    return {**head, "properties": dict(zip(names, o["values"], strict=True)), "methods": methods}


def _show_function(h: Handle, f: dict, view: str) -> dict | str:
    n, off = f["script"], f["offset"]
    lines = _flow(h, n, off)[0]
    if view == "asm":
        return "\n".join(lines)
    if view == "hex":
        raw = script(h, n)["data"][off : off + min(f["size"], HEX_VIEW)]
        return {"address": f"0x{f['address']:x}", "size": f["size"], "hex": raw.hex()}
    if view == "object":
        me = _decoded(h, n)[1][off][2]
        if me is None:
            raise Fail("bad_input", f"{f['name']} is a procedure; no object owns it")
        return _object_view(h, n, me)
    outs, ins = _index(h)
    out = _public(f)
    out["callers"] = len({i["ref"] for i in ins.get(f["address"], []) if i["type"] == "call"})
    out["callees"] = len({i["ref"] for i in outs[f["address"]] if i["type"] in ("call", "import")})
    if view == "auto":
        out["asm"] = "\n".join(lines[:AUTO_ASM_LINES])
        if len(lines) > AUTO_ASM_LINES:
            out["asm_lines"] = len(lines)
    return out


def show(handle: Handle, ref: str, view: str = "auto") -> dict | str:
    """A function (``asm``, ``hex``, ``object`` for its owner, ``info``, ``auto`` = info plus
    40 asm lines), an object (its properties and methods), a resource, kernel or selector."""
    if view not in SHOW_VIEWS:
        raise Fail("bad_input", f"unknown view {view!r}", "one of " + ", ".join(SHOW_VIEWS))
    kind, item = _resolve(handle, ref)
    if kind == "function":
        return _show_function(handle, item, view)
    if kind == "object":
        if view in ("asm", "hex"):
            raise Fail("bad_input", f"{item['name']} is an object; show one of its methods")
        n = item["script"]
        o = next(
            o for o in script(handle, n)["objects"] if n << 16 | o["address"] == item["address"]
        )
        return _object_view(handle, n, o)
    if kind == "resource":
        if view in ("asm", "object"):
            raise Fail("bad_input", f"{ref} is a resource; views are info and hex")
        data = resource(handle, *item)
        out = {"id": f"{TYPES[item[0]]}:{item[1]}", "size": len(data)}
        if view == "hex":
            return {**out, "hex": data[:HEX_VIEW].hex(), "complete": len(data) <= HEX_VIEW}
        if item[0] == SCRIPT:
            out["blocks"] = script(handle, item[1])["blocks"]
        return out
    names = _vocab(handle, VOCAB_KERNELS if kind == "kernel" else VOCAB_SELECTORS)
    users = {i["ref"] for i in _index(handle)[1].get(f"{kind}:{item}", [])}
    return {
        "name": item,
        "ref": f"{kind}:{item}",
        "number": names.index(item),
        "users": len(users),
    }


def xrefs(handle: Handle, ref: str, direction: str = "both") -> builtins.list[dict] | Finding:
    """References out of a function (``from``) or into a function, object, kernel or selector
    (``to``). ``ref`` and ``name`` are the other end; ``at`` is the instruction."""
    if direction not in ("to", "from", "both"):
        raise Fail("bad_input", f"unknown direction {direction!r}", "to, from or both")
    kind, item = _resolve(handle, ref)
    if kind == "resource":
        raise Fail("unsupported", "resources have no xrefs; scripts load them by number")
    key = item["address"] if kind in ("function", "object") else f"{kind}:{item}"
    outs, ins = _index(handle)
    items = []
    for side, table in (("from", outs), ("to", ins)):
        if direction in (side, "both"):
            extra = {"direction": side} if direction == "both" else {}
            items.extend(_public({**i, **extra}) for i in table.get(key, []))
    unknowns = [*dict.fromkeys(handle.unknowns)]
    if any(i["type"] == "call" and str(i["ref"]).startswith("selector:") for i in items):
        unknowns.append(UNRESOLVED)
    return Finding(items, "observed", tuple(unknowns)) if unknowns else items
