"""Native binaries: ELF, Mach-O (thin or FAT) and PE through lief and capstone.

The builtin engine needs no reverse-engineering application. It inventories
functions, symbols, strings, sections, imports and exports, disassembles with
capstone and builds one whole-binary xref index: calls, tail jumps, adrp+add
and adrp+ldr pairs, RIP-relative operands, and stubs mapped to imports.
Pseudocode needs Ghidra, which arrives in P1. Engine choice follows design
section 6: explicit, then ``CLEANROOM_ENGINE``, then ``ENGINE_ORDER``.
"""

from __future__ import annotations

import bisect
import json
import os
import platform
import re
import struct
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from operator import itemgetter
from typing import Any

import capstone as cs
import lief

from cleanroom import engines, proc
from cleanroom.evidence import Finding
from cleanroom.target import Fail, Target, is_fat_macho, parse_ref, read_head

ENGINE_ORDER = ("ghidra", "hopper", "builtin")
ENGINES = (*ENGINE_ORDER, "ida")
# Engines this module can drive today; the others name the phase that adds them.
DRIVEN = ("builtin",)
ARRIVES = {"ghidra": "P1", "hopper": "P3", "ida": "the backlog"}
INSTALL = {
    "ghidra": "install Ghidra (free), set GHIDRA_INSTALL_DIR and add the [ghidra] extra",
    "hopper": "install Hopper Disassembler under /Applications",
    "ida": "install IDA Pro 9 with idalib and set IDADIR",
}
LIST_WHAT = ("functions", "symbols", "strings", "sections", "imports", "exports")
SHOW_VIEWS = ("auto", "info", "asm", "bytes", "pseudo")
BUILTIN_VIEWS = ("auto", "info", "asm", "bytes")  # what open advertises: no decompiler
DIFF_KEYS = {
    "functions": "name",
    "symbols": "name",
    "strings": "value",
    "sections": "name",
    "imports": "name",
    "exports": "name",
}
DIFF_IGNORE = {"address", "offset", "size"}
MACHO_MAGICS = (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe")
ARCH_NAMES = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x86_64", "amd64": "x86_64"}
CS_MODES = {"arm64": (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM), "x86_64": (cs.CS_ARCH_X86, cs.CS_MODE_64)}
HEX_KEYS = ("address", "ref", "at")
MIN_STRING = 4
BYTES_VIEW = 256
AUTO_ASM_LINES = 40
MATCH_BUDGET = 5.0
INDEX_BUDGET = 60.0  # seconds the whole-binary xref index may take before it stops
# Bytes decoded per function (the rest is an unknown) and instructions capstone holds at once.
DISASM_MAX, DISASM_CHUNK = 1 << 20, 4096
FUZZY_MIN = 3  # a suffix or substring ref shorter than this is not_found, not a guess
HINT = "try list functions --match"
PLT_STRIDE = 16
PRINTABLE = re.compile(rb"[\t\x20-\x7e]{%d,}" % MIN_STRING)
HEX = re.compile(r"[0-9a-fA-F]+")
# The regex child: user patterns run here under proc.run_limited, so one that backtracks
# without bound is killed at the deadline instead of stalling the server (it holds the GIL).
RX_CHILD = (
    "import json, re, sys\np, texts = json.load(sys.stdin)\nrx = re.compile(p, re.I)\n"
    "print(*(i for i, t in enumerate(texts) if rx.search(t)))\n"
)


def detect(path: str, head: bytes) -> bool:
    """Mach-O (thin or FAT), ELF or PE, by magic bytes; never by suffix."""
    if head[:4] in MACHO_MAGICS or head[:4] == b"\x7fELF" or is_fat_macho(head):
        return True
    if head[:2] != b"MZ" or len(head) < 0x40:
        return False
    off = struct.unpack_from("<I", head, 0x3C)[0]
    if off + 4 > len(head):
        if off > 1 << 20:
            return False
        head = read_head(path, off + 4)
    return head[off : off + 4] == b"PE\0\0"


def choose_engine(engine: str | None) -> str:
    """Explicit engine, then CLEANROOM_ENGINE, then the first installed one in ENGINE_ORDER.

    IDA is never chosen automatically. A named engine that is absent fails
    ``engine_missing``; one that is present but not driven yet fails ``unsupported``.
    """
    name = engine or os.environ.get("CLEANROOM_ENGINE") or ""
    if not name:
        return next((e for e in ENGINE_ORDER if e in DRIVEN and engines.probe(e)), "builtin")
    if name not in ENGINES:
        raise Fail("bad_input", f"unknown engine {name!r}", "one of " + ", ".join(ENGINES))
    if engines.probe(name) is None:
        raise Fail("engine_missing", f"engine {name} is not installed", INSTALL.get(name))
    if name not in DRIVEN:
        raise Fail(
            "unsupported", f"engine {name} arrives in {ARRIVES[name]}", "use engine=builtin"
        )
    return name


@dataclass
class Handle:
    """One opened slice: the lief binary, its identity and lazily built tables."""

    binary: Any
    fmt: str
    arch: str
    slices: list[str]
    fat: bool
    base: int
    sha256: str
    engine: str
    sections: list[dict]
    cache: dict[str, Any] = field(default_factory=dict)
    unknowns: list[str] = field(default_factory=list)
    # The FatBinary that owns a Mach-O slice: lief frees the slice with its parent.
    owner: Any = None


def _enum_name(value: Any) -> str:
    return str(value).rsplit(".", 1)[-1].lower()


def _cpu_name(header: Any) -> str:
    cpu = header.cpu_type
    if cpu == lief.MachO.Header.CPU_TYPE.ARM64:
        return "arm64e" if header.cpu_subtype & 0xFF == 2 else "arm64"
    if cpu == lief.MachO.Header.CPU_TYPE.X86_64:
        return "x86_64"
    return _enum_name(cpu)


def _parse(path: str, arch: str | None) -> tuple[Any, Any, str, str, list[str], bool]:
    """(binary, owner, format, arch, slice names, fat) for the slice ``arch`` wants."""
    head = read_head(path, 8)
    if head[:4] in MACHO_MAGICS or is_fat_macho(head):
        fat = lief.MachO.parse(path)
        slices = {} if fat is None else {_cpu_name(b.header): b for b in fat}
        if not slices:
            raise Fail("failed", f"lief cannot parse {path}")
        want = ARCH_NAMES.get(arch or platform.machine(), arch or platform.machine())
        pick = next((n for n in slices if n == want or (want, n) == ("arm64", "arm64e")), None)
        if pick is None and arch is None and len(slices) == 1:
            pick = next(iter(slices))
        if pick is None:
            have = "available: " + ", ".join(slices)
            raise Fail("bad_input", f"no {want} slice in {path}", have)
        return slices[pick], fat, "macho", pick, [*slices], is_fat_macho(head)
    b = lief.parse(path)
    if isinstance(b, lief.ELF.Binary):
        fmt, have = "elf", _enum_name(b.header.machine_type)
    elif isinstance(b, lief.PE.Binary):
        fmt, have = "pe", _enum_name(b.header.machine)
    else:
        raise Fail("failed", f"lief cannot parse {path}")
    have = {"aarch64": "arm64", "amd64": "x86_64"}.get(have, have)
    if arch and ARCH_NAMES.get(arch, arch) != have:
        raise Fail("bad_input", f"{path} is {have}, not {arch}")
    return b, None, fmt, have, [have], False


def _sections(b: Any, fmt: str, base: int) -> list[dict]:
    """Mapped sections with absolute addresses.

    ``_cstring`` marks NUL-separated literal pools and ``_stub`` the import
    trampolines (Mach-O symbol stubs, ELF ``.plt*``), which are not functions.
    """
    out = []
    for s in b.sections:
        flags = {_enum_name(f) for f in (s.characteristics_lists if fmt == "pe" else s.flags_list)}
        stub = False
        if fmt == "macho":  # offsets are file offsets: the FAT slice start is added back
            rec = (
                f"{s.segment_name},{s.name}",
                s.virtual_address,
                s.size,
                s.offset + b.fat_offset,
            )
            exe = bool({"pure_instructions", "some_instructions"} & flags)
            text = s.type == lief.MachO.Section.TYPE.CSTRING_LITERALS
            stub = s.type == lief.MachO.Section.TYPE.SYMBOL_STUBS and s.reserved2 > 0
        elif fmt == "elf":
            rec = (s.name, s.virtual_address, s.size, s.offset)
            exe, text = "execinstr" in flags, s.name.startswith(".rodata") or "strings" in flags
            stub = s.name.startswith(".plt")
            if "alloc" not in flags:
                continue
        else:
            rec = (s.name, base + s.virtual_address, s.virtual_size or s.sizeof_raw_data, s.offset)
            exe, text = "mem_execute" in flags, False
        if rec[2]:
            name, addr, size, off = rec
            keys = {"name": name, "address": addr, "size": size, "offset": off, "exec": exe}
            out.append({**keys, "_cstring": text, "_stub": stub, "_obj": s})
    return out


def open(target: Target, engine: str | None = None, arch: str | None = None) -> Handle:
    """Bind one slice of a native file to the builtin engine."""
    choose_engine(engine)
    b, owner, fmt, have, slices, fat = _parse(target.path, arch)
    label = f"builtin ({engines.probe('builtin')})"
    secs = _sections(b, fmt, b.imagebase)
    return Handle(b, fmt, have, slices, fat, b.imagebase, target.sha256, label, secs, owner=owner)


def close(handle: Handle) -> None:
    """Nothing to release: lief holds the file in memory and no worker runs."""


def info(handle: Handle) -> dict:
    return {
        "format": handle.fmt,
        "fat": handle.fat,
        "slices": handle.slices,
        "arch": handle.arch,
        "engine": handle.engine,
        "entry": f"0x{handle.binary.entrypoint:x}",
        "image_base": f"0x{handle.base:x}",
        "sha256": handle.sha256,
        "views": [*BUILTIN_VIEWS],
    }


def _abs(h: Handle, addr: int) -> int:
    """function_starts and PE tables are base-relative; symbols are absolute."""
    return addr if addr >= h.base else addr + h.base


def _section_at(h: Handle, addr: int) -> dict | None:
    for s in h.sections:
        if s["address"] <= addr < s["address"] + s["size"]:
            return s
    return None


def _read(h: Handle, addr: int, n: int) -> bytes:
    return bytes(h.binary.get_content_from_virtual_address(addr, n))


def _public(item: dict) -> dict:
    """Drop private keys and render addresses as ``0x..`` text."""
    return {
        k: f"0x{v:x}" if k in HEX_KEYS and isinstance(v, int) else v
        for k, v in item.items()
        if not k.startswith("_")
    }


def _cs_arch(h: Handle) -> str:
    """The capstone family: arm64e disassembles as arm64."""
    return "arm64" if h.arch.startswith("arm64") else h.arch


def _disassembler(h: Handle) -> cs.Cs:
    if "md" not in h.cache:
        if _cs_arch(h) not in CS_MODES:
            what = f"builtin disassembles arm64 and x86_64, not {h.arch}"
            raise Fail("unsupported", what, "use Ghidra")
        md = cs.Cs(*CS_MODES[_cs_arch(h)])
        md.detail = True
        h.cache["md"] = md
    return h.cache["md"]


def _functions(h: Handle) -> list[dict]:
    """Function starts from symbols and function_starts, absolute, sorted, sized to the next.

    lief's unnamed Mach-O entries come from compact unwind and include a range
    sentinel, so the unnamed starts are taken from LC_FUNCTION_STARTS instead.
    """
    b, macho = h.binary, h.fmt == "macho"
    found = [(f.address, f.name) for f in b.functions if f.name or not macho]
    found.append((b.entrypoint, ""))
    if macho and b.has_function_starts:
        found.extend((a, "") for a in b.function_starts.functions)
    starts: dict[int, str] = {}
    for raw, name in found:
        addr = _abs(h, raw)
        sec = _section_at(h, addr)
        if sec and sec["exec"] and not sec["_stub"]:
            starts[addr] = starts.get(addr) or name
    addrs = sorted(starts)
    out = []
    for i, addr in enumerate(addrs):
        sec = _section_at(h, addr)
        end = sec["address"] + sec["size"]
        nxt = addrs[i + 1] if i + 1 < len(addrs) and addrs[i + 1] < end else end
        out.append(
            {"name": starts[addr], "address": addr, "size": nxt - addr, "_section": sec["name"]}
        )
    return out


def _symbols(h: Handle) -> list[dict]:
    """Named symbols once each; Mach-O debug (STAB) entries are skipped."""
    seen, out = set(), []
    for s in h.binary.symbols:
        if not s.name or (h.fmt == "macho" and s.raw_type & 0xE0) or (s.name, s.value) in seen:
            continue
        seen.add((s.name, s.value))
        sec = _section_at(h, s.value)
        typ = (
            "undef" if not s.value else "func" if sec and sec["exec"] else "data" if sec else "abs"
        )
        out.append({"name": s.name, "address": s.value, "type": typ})
    return out


def _string(sec: dict, pos: int, raw: bytes) -> dict:
    item = {"address": sec["address"] + pos, "section": sec["name"]}
    try:
        item["value"] = raw.decode("utf-8")
    except UnicodeDecodeError:
        item["bytes"] = raw.hex()
    return item


def _strings(h: Handle) -> list[dict]:
    """Literal pools split on NUL (so a 4 KB literal stays whole); printable runs elsewhere."""
    out = []
    for sec in h.sections:
        if sec["exec"]:
            continue
        data = bytes(sec["_obj"].content)
        if sec["_cstring"]:
            pos = 0
            for chunk in data.split(b"\0"):
                if chunk:
                    out.append(_string(sec, pos, chunk))
                pos += len(chunk) + 1
        else:
            out.extend(_string(sec, m.start(), m.group()) for m in PRINTABLE.finditer(data))
    return out


def _library(sym: Any) -> str:
    info = sym.binding_info if getattr(sym, "has_binding_info", False) else None
    lib = info.library if info is not None and info.has_library else None
    return lib.name if lib is not None else ""


def _imports(h: Handle) -> list[dict]:
    if h.fmt == "pe":
        return [
            {"name": e.name or f"ordinal#{e.ordinal}", "library": imp.name}
            for imp in h.binary.imports
            for e in imp.entries
        ]
    syms = {s.name: s for s in h.binary.imported_symbols if h.fmt != "macho" or not s.value}
    return [{"name": name, "library": _library(s)} for name, s in syms.items()]


def _exports(h: Handle) -> list[dict]:
    if h.fmt == "pe":
        fns = h.binary.exported_functions
        return [{"name": f.name, "address": _abs(h, f.address)} for f in fns]
    return [{"name": s.name, "address": s.value} for s in h.binary.exported_symbols]


BUILDERS = {
    "functions": _functions,
    "symbols": _symbols,
    "strings": _strings,
    "sections": lambda h: h.sections,
    "imports": _imports,
    "exports": _exports,
}


def _table(h: Handle, what: str) -> list[dict]:
    if what not in h.cache:
        h.cache[what] = BUILDERS[what](h)
    return h.cache[what]


def _regex(items: list[dict], texts: list[str], pattern: str) -> list[dict] | Finding:
    """Items whose text ``pattern`` matches, searched in a child killed at MATCH_BUDGET."""
    try:
        re.compile(pattern)  # syntax errors are reported here; matching runs in the child
    except re.error as e:
        raise Fail("bad_input", f"bad regex /{pattern}/: {e}") from None
    argv, feed = [sys.executable, "-I", "-c", RX_CHILD], json.dumps([pattern, texts]).encode()
    try:
        done = proc.run_limited(argv, MATCH_BUDGET, 1 << 24, stdin=feed)
    except Fail as e:
        if e.code != "timeout":
            raise
        why = f"regex match killed after {MATCH_BUDGET:g} s; narrow the pattern"
        return Finding([], "observed", (why,))
    if done.returncode or done.truncated:
        raise Fail("failed", f"regex child failed: {done.stderr.decode(errors='replace')[-200:]}")
    return [items[int(i)] for i in done.stdout.split()]


def _match(items: list[dict], match: str | None) -> list[dict] | Finding:
    """Case-insensitive substring under a wall-clock budget, or ``/re/`` through ``_regex``."""
    if not match:
        return items
    texts = [str(i.get("name") or i.get("value") or i.get("bytes") or "") for i in items]
    if len(match) > 2 and match[0] == match[-1] == "/":
        return _regex(items, texts, match[1:-1])
    low, deadline, out = match.lower(), time.monotonic() + MATCH_BUDGET, []
    for i, text in enumerate(texts):
        if low in text.lower():
            out.append(items[i])
        if time.monotonic() > deadline:
            why = f"match stopped after {MATCH_BUDGET:g} s at item {i + 1} of {len(items)}"
            return Finding(out, "observed", (why,))
    return out


def list(handle: Handle, what: str, match: str | None = None) -> list[dict] | Finding:
    """Inventory of ``what`` (see LIST_WHAT), optionally filtered by ``match``."""
    if what not in LIST_WHAT:
        raise Fail("bad_input", f"unknown what {what!r}", "one of " + ", ".join(LIST_WHAT))
    return _match([_public(i) for i in _table(handle, what)], match)


def _containing(funcs: list[dict], addr: int) -> dict | None:
    i = bisect.bisect_right(funcs, addr, key=itemgetter("address")) - 1
    if i >= 0 and addr < funcs[i]["address"] + funcs[i]["size"]:
        return funcs[i]
    return None


def _resolve(h: Handle, ref: str) -> dict:
    """The function a ref names, in order: containing address; exact or ``_``-prefixed name;
    bare hex (design 9, case 1: ``add`` first, 0xadd second); suffix or substring of FUZZY_MIN+."""
    funcs = _table(h, "functions")
    kind, value = parse_ref(ref)[:2]
    if kind == "addr":
        f = _containing(funcs, value)
        if f is None:
            raise Fail("not_found", f"{ref} is not inside a known function", HINT)
        return f
    if not value:
        raise Fail("bad_input", "ref is empty")
    hits = [f for f in funcs if f["name"] in (value, "_" + value)]
    hits = [f for f in hits if f["name"] == value] or hits
    tried = ""
    if not hits and HEX.fullmatch(value):
        if f := _containing(funcs, int(value, 16)):
            return f
        tried = f", and 0x{value} is not inside a known function"
    if not hits and len(value) >= FUZZY_MIN:
        hits = [f for f in funcs if f["name"].endswith(value)]
        hits = hits or [f for f in funcs if value in f["name"]]
    if not hits:
        raise Fail("not_found", f"no function named {value!r}{tried}", HINT)
    if len(hits) > 1:
        names = ", ".join(f"{f['name']}@0x{f['address']:x}" for f in hits[:12])
        raise Fail("ambiguous", f"{value!r} matches {len(hits)} functions", "candidates: " + names)
    return hits[0]


def _insns(h: Handle, addr: int, size: int) -> Iterator[Any]:
    """Instructions from ``addr``, DISASM_CHUNK at a time (capstone materialises every one it
    is asked for, detail included); stops at DISASM_MAX bytes or the first undecodable byte."""
    md, end = _disassembler(h), addr + min(size, DISASM_MAX)
    while addr < end:
        last = None
        for last in md.disasm(_read(h, addr, end - addr), addr, DISASM_CHUNK):
            yield last
        if last is None:
            return
        addr = last.address + last.size


def _asm(h: Handle, f: dict) -> str:
    insns = _insns(h, f["address"], f["size"])
    lines = [f"0x{i.address:x}: {i.mnemonic} {i.op_str}".rstrip() for i in insns]
    if not lines:
        raise Fail("failed", f"capstone decoded nothing at 0x{f['address']:x}")
    return "\n".join(lines)


def show(handle: Handle, ref: str, view: str = "auto") -> dict | str:
    """One function: ``info``, ``asm``, ``bytes`` (first 256), or ``auto`` = info plus 40 lines."""
    if view not in SHOW_VIEWS:
        raise Fail("bad_input", f"unknown view {view!r}", "one of " + ", ".join(SHOW_VIEWS))
    if view == "pseudo":
        hint = "install Ghidra (free) and set GHIDRA_INSTALL_DIR"
        raise Fail("unsupported", "builtin has no decompiler", hint)
    f = _resolve(handle, ref)
    addr, size = f["address"], f["size"]
    if view == "asm":
        text = _asm(handle, f)
        if size <= DISASM_MAX:
            return text
        return Finding(text, "observed", (f"disassembly stops at {DISASM_MAX} of {size} bytes",))
    if view == "bytes":
        raw = _read(handle, addr, min(size, BYTES_VIEW))
        head = {"address": f"0x{addr:x}", "size": size}
        return {**head, "hex": raw.hex(), "complete": size <= len(raw)}
    outs, ins = _index(handle)
    flow = ("call", "jump", "import")
    out = {"name": f["name"], "address": f"0x{addr:x}", "size": size, "section": f["_section"]}
    out["callers"] = len({i["ref"] for i in ins.get(addr, []) if i["type"] in flow})
    out["callees"] = len({i["ref"] for i in outs.get(addr, []) if i["type"] in flow})
    if view == "auto":
        lines = _asm(handle, f).splitlines()
        out["asm"] = "\n".join(lines[:AUTO_ASM_LINES])
        if len(lines) > AUTO_ASM_LINES:
            out["asm_lines"] = len(lines)
    return out


def _targets(h: Handle, insn: Any, pages: dict) -> list[tuple[str, int]]:
    """``(call|jump|data, address)`` pairs one instruction refers to.

    ``pages`` carries adrp results per register so the following add or ldr
    completes the address; it is per function, so a stale page cannot cross one.
    """
    ops = insn.operands
    flow = "call" if insn.group(cs.CS_GRP_CALL) else "jump" if insn.group(cs.CS_GRP_JUMP) else ""
    out = []
    if _cs_arch(h) == "arm64":
        imm, mem, reg = cs.arm64.ARM64_OP_IMM, cs.arm64.ARM64_OP_MEM, cs.arm64.ARM64_OP_REG
        if insn.mnemonic == "adrp":
            pages[ops[0].reg] = ops[1].imm
        elif insn.mnemonic == "adr":
            out.append(("data", ops[1].imm))
        elif insn.mnemonic == "add" and len(ops) == 3 and ops[2].type == imm:
            if ops[1].type == reg and ops[1].reg in pages:
                out.append(("data", pages.pop(ops[1].reg) + ops[2].imm))
        else:
            for o in ops:
                if o.type == mem and o.mem.base in pages:
                    out.append(("data", pages[o.mem.base] + o.mem.disp))
                elif o.type == imm and flow:
                    out.append((flow, o.imm))
        return out
    for o in ops:
        if o.type == cs.x86.X86_OP_MEM and o.mem.base == cs.x86.X86_REG_RIP:
            out.append((flow or "data", insn.address + insn.size + o.mem.disp))
        elif o.type == cs.x86.X86_OP_IMM and flow:
            out.append((flow, o.imm))
    return out


def _slots(h: Handle) -> dict[int, str]:
    """GOT or IAT slot address -> import name: Mach-O bindings, ELF relocations, PE IAT."""
    b = h.binary
    if h.fmt == "macho":
        return {x.address: x.symbol.name for x in b.bindings if x.symbol and x.symbol.name}
    if h.fmt == "elf":
        return {r.address: r.symbol.name for r in b.relocations if r.has_symbol and r.symbol.name}
    return {_abs(h, e.iat_address): e.name for i in b.imports for e in i.entries if e.name}


def _stubs(h: Handle, slots: dict[int, str]) -> dict[int, str]:
    """Stub address -> import name via Mach-O indirect symbols or the ELF PLT's GOT slot.

    An entry that resolves to nothing is named ``stub@0x..``; an edge that
    reaches it adds an unknown. PE calls go through the IAT, so it has no stubs.
    """
    out, b = {}, h.binary
    stubs = [s for s in h.sections if s["_stub"]]
    if h.fmt == "macho":
        dysym = b.dynamic_symbol_command if b.has_dynamic_symbol_command else None
        names = [s.name for s in dysym.indirect_symbols] if dysym else []
        for sec in stubs:
            s, start = sec["_obj"], sec["address"]
            for i, addr in enumerate(range(start, start + sec["size"], s.reserved2)):
                j = s.reserved1 + i
                out[addr] = (names[j] if j < len(names) else "") or f"stub@0x{addr:x}"
    elif h.fmt == "elf":
        md = _disassembler(h)
        for sec in stubs:
            for addr in range(sec["address"], sec["address"] + sec["size"], PLT_STRIDE):
                pages: dict = {}
                insns = md.disasm(_read(h, addr, PLT_STRIDE), addr)
                hits = [slots[t] for i in insns for _, t in _targets(h, i, pages) if t in slots]
                out[addr] = hits[0] if hits else f"stub@0x{addr:x}"
    return out


def _edge(h: Handle, how: str, target: int, t: dict) -> tuple[str, str] | None:
    """``(type, target name)`` for one reference, or None when it stays inside a function."""
    if target in t["stubs"] or target in t["slots"]:
        return "import", t["stubs"].get(target) or t["slots"][target]
    if how != "data":
        return (how, t["starts"][target]) if target in t["starts"] else None
    if target in t["strings"]:
        return "string", ""
    sec = _section_at(h, target)
    if sec is None or sec["exec"]:
        return ("data", t["starts"][target]) if target in t["starts"] else None
    return "data", t["symtab"].get(target, "")


def _build_index(h: Handle) -> tuple[dict[int, list], dict[int, list]]:
    """Disassemble every function once; edges out of and into each start or data address."""
    funcs, slots = _table(h, "functions"), _slots(h)
    t = {
        "starts": {f["address"]: f["name"] for f in funcs},
        "stubs": _stubs(h, slots),
        "slots": slots,
        "strings": {s["address"] for s in _table(h, "strings")},
        "symtab": {s["address"]: s["name"] for s in _table(h, "symbols") if s["address"]},
    }
    named: dict[str, list[int]] = {}  # import, slot and data symbol names the index knows
    for addr, name in [*t["stubs"].items(), *t["slots"].items(), *t["symtab"].items()]:
        named.setdefault(name, []).append(addr)
    h.cache["named"] = named
    outs: dict[int, list] = {}
    ins: dict[int, list] = {}
    unresolved: set[str] = set()
    dropped, deadline = 0, time.monotonic() + INDEX_BUDGET
    for n, f in enumerate(funcs):
        if time.monotonic() > deadline:
            h.unknowns.append(f"xref index stopped after {INDEX_BUDGET:g} s: {n}/{len(funcs)}")
            break
        pages: dict = {}
        start, size = f["address"], f["size"]
        if size > DISASM_MAX:
            h.unknowns.append(f"0x{start:x}: only the first {DISASM_MAX} of {size} bytes indexed")
        for insn in _insns(h, start, size):
            for how, target in _targets(h, insn, pages):
                edge = _edge(h, how, target, t)
                if edge is None or (how == "jump" and target == start):
                    dropped += (
                        edge is None and how != "data" and not start <= target < start + size
                    )
                    continue
                typ, name = edge
                if name.startswith("stub@"):
                    unresolved.add(name)
                outs.setdefault(start, []).append(
                    {"ref": target, "name": name, "type": typ, "at": insn.address}
                )
                ins.setdefault(target, []).append(
                    {"ref": start, "name": f["name"], "type": typ, "at": insn.address}
                )
    if dropped:
        h.unknowns.append(f"{dropped} call or jump targets outside known functions were dropped")
    h.unknowns.extend(f"{s}: import name not resolved" for s in sorted(unresolved))
    return outs, ins


def _index(h: Handle) -> tuple[dict[int, list], dict[int, list]]:
    if "index" not in h.cache:
        h.cache["index"] = _build_index(h)
    return h.cache["index"]


def _keys_for(h: Handle, ref: str, known: set[int]) -> list[int]:
    """Index keys for ``ref``: its function's start; else an address (explicit or bare hex)
    or the name of an import stub, GOT slot or data symbol, when the index has edges there."""
    try:
        return [_resolve(h, ref)["address"]]
    except Fail as e:
        if e.code != "not_found":
            raise
        kind, value = parse_ref(ref)[:2]
        if kind == "name" and HEX.fullmatch(value):
            kind, value = "addr", int(value, 16)
        names = h.cache["named"]
        hits = [value] if kind == "addr" else names.get(value) or names.get("_" + value) or []
        if not any(k in known for k in hits):
            raise
        return [k for k in hits if k in known]


def xrefs(handle: Handle, ref: str, direction: str = "both") -> list[dict] | Finding:
    """References into (``to``), out of (``from``) or both ways from a function or address.

    Each item names the other end: ``ref`` and ``name`` are the target for
    ``from`` and the referring function for ``to``; ``at`` is the instruction.
    """
    if direction not in ("to", "from", "both"):
        raise Fail("bad_input", f"unknown direction {direction!r}", "to, from or both")
    outs, ins = _index(handle)
    keys = _keys_for(handle, ref, ins.keys() | outs.keys())
    items = []
    for side, table in (("from", outs), ("to", ins)):
        if direction in (side, "both"):
            extra = {"direction": side} if direction == "both" else {}
            items.extend(_public({**i, **extra}) for k in keys for i in table.get(k, []))
    if handle.unknowns:
        return Finding(items, "observed", tuple(dict.fromkeys(handle.unknowns)))
    return items
