# CleanRoom design

CleanRoom is a local-only Python 3.12 reimplementation of morluto/rea (MIT; about 185,000 lines of layered TypeScript and 139 MCP tools). It keeps the analysis surface and drops repeated layers. Facts about rea come from a survey of commit `46c9cba`, kept in [research/](research/).

## 1. Goal and non-goals

Goal: rea's analysis power in a local tool under 8,000 lines of source. Tests live in `tests/` and are not counted. Every finding is pageable Evidence. Prefer existing parsers, state uncertainty, and never execute targets for static inspection. Every tool has a deadline and an output bound.

Version 1 does not include:

- Cloud decompilers: CleanRoom never sends code to a vendor's cloud decompiler.
- Windows support.
- GUI cursor tools.
- A JavaScript semantic intermediate representation.
- A reconstruction ledger or reconstruction coverage evaluator.
- Unknown revision chains.
- Analysis snapshots.
- Byte-compatible rea Evidence IDs.
- A configuration writer for 19 agent clients.
- README translations.

The survey notes record how rea does each deferred feature, in case v2 wants one: [rea-core.md](research/rea-core.md) for snapshots, unknowns and the reconstruction ledger; [rea-js-web.md](research/rea-js-web.md) for the semantic graph.

## 2. Rules

1. **One `@tool` registry.** A typed function produces its MCP tool, CLI subcommand, and catalog entry. Its type hints are the schema and its docstring is the description.
2. **One Evidence type.** Every tool returns Evidence; derived results link inputs.
3. **One module per target kind.** It owns detection, inventory, and `list`/`show` vocabulary.
4. **One worker protocol.** Heavy engines use newline-delimited JSON over stdio. Hopper uses AF_UNIX because it launches the script, with the same protocol.
5. **Plain dictionaries inside.** Validate only at the MCP boundary.
6. **No ports, adapters, or services.** Call libraries and workers directly; add helpers only to remove duplication.

This replaces rea's duplicated contracts, schemas, examples, CLI lists, and server registrations ([rea-core.md](research/rea-core.md): `src/contracts/toolEffects.ts`, `src/server/registerInvestigationTools.ts`, `src/cliCommandNames.ts`).

## 3. Verbs

These verbs replace rea tool families. `list` is paged; `show` selects a view. Results are Evidence; refs are target-specific.

| Verb | Inputs | Meaning |
|---|---|---|
| `open` | `target`, `kind?`, `engine?`, `arch?` | Detect and bind a target. `kind` overrides detection (needed for EVM bytecode); `engine` picks a native engine; `arch` picks a FAT slice; default is the host architecture. |
| `close` | none | Close the active target and its workers. Keep session Evidence. |
| `list` | `what`, `match?`, `offset=0`, `limit=200` | List target-specific items such as functions, strings, files, classes, requests or regions. |
| `show` | `ref`, `view=auto` | Inspect one target-specific item, selecting a useful view by default. |
| `xrefs` | `ref`, `direction=to\|from\|both` | Return references into, out of, or both ways from an item. |
| `trace` | `start`, `goal?`, `depth=3` | Run one breadth-first search over xrefs for every supported kind. No per-kind traversal framework. |
| `extract` | `target`, `out_dir` | Unpack ZIP, ASAR, DMG or firmware (`unblob`), or unbundle JavaScript (`wakaru`), into a new caller-named directory with bounded writes. |
| `diff` | `a`, `b`, `what?` | Run one keyed diff over `list` output. Report added, removed, changed, or unknown. |
| `run` | `argv` or `url`, `steps?`, `breakpoints?`, `timeout=30` | Capture a local process or browser run. Keep static inspection separate from execution. |
| `annotate` | `ref`, `name?`, `comment?` | Apply supported native annotations and read them back. Unsupported engines return a clear error. |
| `evidence` | `id?`, `offset?`, `export?`, `import?` | Retrieve and page Evidence, or export/import its JSONL records. |
| `doctor` | none | Report installed engines, libraries, and local prerequisites. |

`trace` is one xref BFS for every kind. `diff` uses kind-specific stable keys; incomplete inventories produce `unknown`, not added/removed claims. This retains rea's three-way comparison status ([rea-core.md](research/rea-core.md), `src/domain/comparisonStatus.ts`).

### How a call flows

`open` reads the target's first bytes, asks each kind's `detect`, and binds the first match. Kinds are tried most specific first: `dotnet` before `native`, `android` before `apple`, and `firmware` last. Every other verb looks up the bound kind's module and calls the function of the same name. `tools.py` wraps the return value in Evidence, records it in the ledger, pages it if large, and hands it to MCP or the CLI. `trace` and `diff` live in `graph.py` and call the kind's `xrefs` and `list`, so no kind implements them.

A kind is a plain module. A missing function means the verb is unsupported for that kind.

```python
# cleanroom/kinds/<kind>.py
def detect(path: str, head: bytes) -> bool: ...
def open(target: Target, engine: str | None) -> Handle: ...
def list(h: Handle, what: str, match: str | None) -> Iterable[dict]: ...
def show(h: Handle, ref: str, view: str) -> dict | str: ...
def xrefs(h: Handle, ref: str, direction: str) -> Iterable[dict]: ...
def close(h: Handle) -> None: ...
```

A kind function returns a plain value. When it infers or misses something, it returns `(value, confidence, unknowns)` instead.

## 4. Targets

A URL is a `web` target. Detect files by content where possible, not suffix alone. Vocabulary is kind-owned.

| Kind | Detect | `list` what | `show` views | Library or engine |
|---|---|---|---|---|
| `native` | ELF, Mach-O (thin or FAT), PE, core file | functions, symbols, strings, sections, imports, exports, threads (cores) | pseudo, asm, info, bytes | Ghidra (`pyghidra`), IDA (`idalib`), Hopper (rea's bridge), or builtin `lief` + `capstone` |
| `js` | Directory with `package.json` or JS files; ASAR header | files, modules, imports, routes, endpoints, channels, addons, sourcemaps | source, info | ASAR reader, `tree-sitter` queries, source maps, `wakaru` subprocess |
| `web` | `http(s)://` URL | scripts, requests, storage, listeners, webmcp | source, request, dom, screenshot | `playwright` |
| `har` | JSON with `log.entries` | requests | request, response | `json` + `jsonschema` |
| `dotnet` | PE with a CLI header | types, methods, fields, refs, pinvokes, resources | il, info | `dnfile` + `dncil` |
| `android` | ZIP with `AndroidManifest.xml` and `classes.dex` | classes, methods, permissions, components | java, smali, info | `androguard`; `jadx` CLI for Java source |
| `firmware` | Fallback for blobs that `binwalk` scans | regions | info | `binwalk` / `unblob` subprocesses |
| `apple` | `.app` bundle, DMG (`koly` trailer), IPA, plist | files, plists, dylibs, entitlements | plist, signature, info | `plistlib`, `lief`, `codesign`, `hdiutil` |
| `evm` | Hex or raw bytecode, by explicit kind | selectors | info | `evmole` |
| `process` | A capture produced by `run` | events, files, processes | screen, output, event | `ptyprocess` + `pyte` + `psutil`; `lldb` tracer |

Choices follow [rea-native.md](research/rea-native.md), [rea-js-web.md](research/rea-js-web.md), and [rea-other-targets.md](research/rea-other-targets.md). Only builtin needs no reverse-engineering application; native capabilities vary (`src/application/AnalysisProvider.ts`, `src/native/NativeMacOSProvider.ts`).

## 5. Evidence

Each operation produces a stable record with inputs, subject, engine, result, confidence, unknowns, locations, and links. The schema is smaller than rea's. IDs are content hashes, not rea-compatible; parity requires RFC 8785 number formatting ([rea-core.md](research/rea-core.md), `src/domain/evidence.ts`).

```python
@dataclass(frozen=True)
class Evidence:
    op: str  # verb that produced it: "show", "trace", ...
    params: dict  # verb arguments, as called
    subject: dict | None  # {path, sha256, kind, format, arch}; None when derived
    engine: str  # "ghidra 12.0.1", "lief 1.0.0 + capstone 5.0.9"
    result: Any
    confidence: Literal["observed", "derived", "inferred"]
    unknowns: tuple[str, ...] = ()  # what was not seen, and why
    locations: tuple[str, ...] = ()  # "0x100003f20", "app.asar!/main.js:12:4"
    links: tuple[str, ...] = ()  # ids of the Evidence this was derived from

    @property
    def id(self) -> str:
        return "ev_" + sha256(canonical(asdict(self))).hexdigest()
```

`canonical` is `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)` encoded as UTF-8. The ID authenticates CleanRoom records, not rea records. Import recomputes every ID and rejects a mismatch.

The session ledger is a dict keyed by ID. Recording an identical record is a no-op; two records cannot share an ID. A result over 64 KB stays in the ledger. The reply carries the first page, the `evidence_id` and the next offset, and `evidence(id, offset)` returns later pages. Export and import use JSONL, one record per line.

`confidence` has three values:

- **observed:** an engine or parser reported it directly.
- **derived:** a deterministic function computed it from other Evidence, as `trace` and `diff` do.
- **inferred:** a heuristic produced it, such as IPC channel pairing or bundler detection.

Incompleteness belongs in `unknowns`, not in a fourth confidence value. Locations are strings for addresses, offsets, paths, or ranges. Links point to input Evidence. The schema omits rea's authority, environment, unknown revision chain, bundle manifest, and snapshot ([rea-core.md](research/rea-core.md), `src/domain/evidence.ts`, `src/domain/residualUnknown.ts`, `src/domain/evidenceBundle.ts`).

## 6. Engines and process safety

Heavy engines run out of process, so a hung decompile or a JVM crash never takes down the server. Each worker imports one shared loop from `worker.py` and registers its handlers. The engine's own Python runs that loop: `pyghidra` for Ghidra, `idalib` for IDA, and Hopper's embedded interpreter. Requests are `{id, op, args}` and replies are `{id, result}` or `{id, error}`, one JSON object per line. Use stdio everywhere except Hopper, which launches the script itself and connects back over a private AF_UNIX socket. The lldb tracer is the one exception to the loop: `run` invokes `engines/rea_lldb_tracer.py` one-shot through `run_limited`, with JSON files in and out.

A worker handles one request at a time. To cancel a request, kill the worker; the next call starts a fresh one. Ghidra keeps its analyzed project under `~/.cache/cleanroom/ghidra/<sha256>`, so a restart skips auto-analysis. The target file is never modified.

Every engine decompiles locally. Cloud decompilers are never needed: Ghidra (free), Hopper and IDA Pro Expert/Ultimate all decompile on the machine. Hard rule: CleanRoom never uses a cloud decompiler.

| Engine | Vendor, price | CleanRoom role |
|---|---|---|
| Ghidra | NSA, free, needs JDK 21 | Default engine. Tested in nightly CI and on the dev Mac |
| Hopper | Cryptic Apps, $99–129 | Optional. P3, tested by hand [MANUALLY] |
| IDA Pro 9+ (`idalib`) | Hex-Rays, about €1.1k–8.6k/yr | Optional, used only when named. The worker refuses `pseudo` unless the decompiler is local. Backlog until someone with an Expert or Ultimate license can test it |
| builtin | lief + capstone | Always available: functions, strings, asm, xrefs; no pseudocode |

Choose an explicit engine, then `CLEANROOM_ENGINE`, then the first installed engine in `ENGINE_ORDER = ("ghidra", "hopper", "builtin")`, one constant in `kinds/native.py`. IDA runs only through `engine="ida"` or `CLEANROOM_ENGINE=ida`. `doctor` lists every engine it finds, with edition hints. Record engine and version in Evidence. rea errors on ambiguity; CleanRoom chooses a predictable local default. After binding, never fail over. Report engine failure. See [rea-core.md](research/rea-core.md), `src/application/AnalysisProvider.ts` and `src/application/binary/AnalysisProviderRegistry.ts`.

`proc.py` owns subprocesses. `run_limited(argv, timeout, rlimits)` uses argument arrays, limits output, and avoids a shell. Long-running children use `start_new_session=True`, an environment token, and `psutil` identity checks. Verify before signaling; fail closed if uncertain ([rea-other-targets.md](research/rea-other-targets.md), `src/process/ProcessOwnership.ts`, `src/process/capture/ProcessCaptureLifecycle.ts`).

Static JavaScript analysis never executes the target. `open(url)` loads the page in a throwaway headless profile. Attaching to a browser the user already runs goes through loopback CDP only. Driving a page or a process takes an explicit `run` with a deadline and bounded output ([rea-js-web.md](research/rea-js-web.md), `src/browser`, `src/application/javascript/JavaScriptArtifactReconstruction.ts`).

## 7. Errors

Raise one `Fail(code, message, hint)` type. MCP and CLI render the same actionable fields. Codes:

| Code | Use |
|---|---|
| `bad_input` | Invalid arguments or malformed input. |
| `not_found` | A target, reference, or Evidence ID does not exist. |
| `ambiguous` | More than one valid match exists. |
| `unsupported` | The target or operation is not supported. |
| `engine_missing` | The requested engine or prerequisite is unavailable. |
| `timeout` | The operation exceeded its deadline. |
| `too_big` | A configured input, output, or result budget was exceeded. |
| `failed` | An operation failed for another reason. |

Usable partial analysis returns Evidence with unknowns, not an error. MCP returns a `Fail` as an `isError` result. The CLI prints it as JSON and exits 1. rea's larger taxonomy is summarized in [rea-core.md](research/rea-core.md), `docs/error-contract.schema.json`.

## 8. Layout and line budgets

Budget: 7,000 counted lines of Python source, 1,000 below the ceiling. Files adapted from rea are listed below and not counted. The per-file figures are individual caps, not targets: they sum to 7,100, so they cannot all be reached at once, and the 7,000 total binds first. Estimates come from the survey notes, for example about 800 lines for .NET and 300 for the Node resolver alone.

```text
cleanroom/
  __main__.py          200   CLI generated from the registry; `cleanroom mcp` serves stdio
  tools.py             450   @tool registry and the 12 verbs
  evidence.py          300   Evidence, ledger, paging, JSONL export/import
  target.py            220   detection, sha256, Fail
  proc.py              300   run_limited, owned process groups
  worker.py            180   JSON-lines loop (worker side) and client
  graph.py             250   trace BFS, keyed three-way diff
  kinds/             4,350
    native.py          600   engine choice, builtin lief + capstone, cores, Hopper launch
    js.py            1,100   ASAR, tree-sitter queries, Node resolver, source maps, IPC
    web.py             400   playwright page, network, screenshot, scenario
    har.py             120
    dotnet.py          800   dnfile + dncil, signature blobs, P/Invoke matching
    android.py         250
    firmware.py        250
    apple.py           450   bundles, DMG, codesign, dylib resolution
    evm.py              60
    process.py         320   PTY capture, filesystem before/after
  engines/             850   counted; adapted files below are not
    __init__.py        100   engine probes for `doctor` and `open`
    ghidra_worker.py   450
    ida_worker.py      300   backlog; needs a licensed IDA Pro 9 to test
    hopper_bridge.py   ~950  adapted from rea's bridge/hopper_bridge.py; not counted
    rea_lldb_tracer.py  839  adapted from rea's bridge/native/rea_lldb_tracer.py; not counted
  skill/SKILL.md             agent guidance, Markdown, not counted
tests/                       not counted; no tests beside source files
```

Check in no generated schemas or catalogs; `cleanroom catalog` prints them from the registry. For what rea's layering costs, see [rea-core.md](research/rea-core.md), section 7.

## 9. Edge cases to carry over

rea learned these the hard way. Carry each into the kind that needs it. Paths are relative to rea's repository root; the survey notes in `research/` have more.

1. A ref with `0x` or `space:0x` is an address. Otherwise try an exact symbol name first, since `add` and `face` are valid hex. Fall back to bare hex only if no symbol matches. An ambiguous name fails and lists the candidates. (`bridge/ghidra/ReaGhidraBridge.java`, `resolveProcedure`)
2. Segment ends are exclusive; function body ranges are inclusive. Report a body's byte count and span separately. (`bridge/ghidra/ReaGhidraBridge.java`)
3. Hopper 6.1 reports a block's end as its last instruction's address. Find the real end by block ownership. (`bridge/hopper_bridge.py`, `_basic_block_end`)
4. Hopper's string display escaping cannot be inverted. Decode the typed bytes, and settle UTF-16 byte order against the display text. (`bridge/hopper_bridge.py`, `_string_record`)
5. Validate every batch rename before changing any name. (`bridge/hopper_bridge.py`, `_validate_name_targets`)
6. Call Hopper's API only on its own Python thread, or it deadlocks. Run regex matching outside that thread with a deadline. (`bridge/hopper_bridge.py`)
7. Hopper cannot load FAT64, so extract the thin slice and add the slice offset back to file offsets. (`src/hopper/HopperFileOffset.ts`)
8. Detect formats by magic bytes, not suffix: the ZIP signature, the ASAR pickle header, `xar!`, and the DMG `koly` trailer 512 bytes from the end. (`src/artifacts/inventory/classify.ts`)
9. Check each ASAR entry's `integrity.hash`, including files in the `.asar.unpacked` companion. (`src/artifacts/AsarArtifactReader.ts`)
10. Source-map paths: prefix `sourceRoot` first; reject paths that escape the root and encoded `%2f` or `%5c`; match `webpack://` names by suffix. (`src/domain/javascript/javascriptSourceMapPaths.ts`)
11. Keep JavaScript UTF-16 offsets apart from Python code points and tree-sitter bytes. Count a BOM as one unit, and accept CR, LF, CRLF, U+2028 and U+2029 line ends.
12. Scan `sourceMappingURL` comments without a backtracking regex, because inline data URLs can be huge. (`src/domain/javascript/javascriptStaticAnalysisCalls.ts`)
13. A package `exports` target never contains `..` or `node_modules`, even encoded, and a missing target does not fall back to `index`. (`src/application/javascript/JavaScriptArtifactPathResolution.ts`)
14. Pair an Electron IPC channel only when it is literal and has exactly one compatible handler. Never pair a dynamic channel. (`src/domain/javascript/electronStaticAnalysis.ts`)
15. Unknown is not absent: an incomplete inventory cannot support an added or removed claim. (`src/domain/comparisonStatus.ts`)
16. Walk ASTs iteratively. A 12,000-deep chain would overflow Python's recursion limit.
17. HAR: reject duplicate JSON keys and validate against HAR 1.2. (`src/browser/history/HarJson.ts`)
18. CDP reuses a `requestId` across redirects, and an unavailable response body is unavailable, not empty. (`src/browser/CdpConnection.ts`)
19. Reject an ambiguous Android overload; never take the first match. (`src/android/JadxSession.ts`)
20. A file that cannot be fully hashed gets no digest, never a prefix digest. Check its identity before and after hashing. (`src/process/capture/FilesystemSnapshot.ts`)
21. Publish extracted output with `O_EXCL | O_NOFOLLOW` and never follow symlinks. If cleanup cannot be confirmed, keep the workspace. (`src/firmware/FirmwarePublication.ts`)
22. If a related process's ownership token cannot be read, fail closed and do not signal it. (`src/process/ProcessOwnership.ts`)

## 10. Setup

Names (decided 2026-10-10, checked with `scripts/check_names.py`):

| What | Name |
|---|---|
| PyPI distribution | `cleanroom-re` |
| Command and Python import package | `cleanroom` |
| Homebrew formula, in our own tap | `cleanroom` |
| GitHub repository | `Sage-is/CleanRoom` |
| License | AGPL-3.0-or-later; adapted rea files keep their MIT notice |

PyPI's `cleanroom` belongs to a dormant 2019 project (huntzhan/cleanroom, 0.4.2), and `clean-room` is blocked as its separator variant. That project installs a top-level `cleanroom` module but no command. The two clash only when both are installed in one environment.

The Homebrew formula in `sage-is/homebrew-apps` is a uv launcher, not a virtualenv with pinned resources. It `depends_on "uv"` and ships a shell script that answers `version` locally and otherwise runs `exec uvx -q --python "${CLEANROOM_PYTHON:-3.13}" --from "cleanroom-re${CLEANROOM_EXTRAS:+[$CLEANROOM_EXTRAS]}==$VERSION" cleanroom "$@"`, so `CLEANROOM_EXTRAS=web,ghidra` pulls the heavy extras. Its caveats say to run `cleanroom doctor` once to warm the uv cache, which avoids MCP startup timeouts.

`cleanroom setup` prints each supported agent's MCP registration, for example `claude mcp add cleanroom -- uvx --from cleanroom-re cleanroom mcp`. Until the package is on PyPI, the command is `uv run --directory <CleanRoom checkout> cleanroom mcp`. Plain `setup` does not edit config. `cleanroom setup --write` edits only Claude Code config, makes a backup, and reports the changed file. It does not reproduce rea's 19-client writer ([rea-core.md](research/rea-core.md), `src/application/SupportedClients.ts`, `src/application/ClientConfigurationDocument.ts`).

Setup copies `skill/` to Claude Code's skill location. The skill covers routing, Evidence, paging, observations, and inferences. `doctor` checks registration, skill, package, and engines.

## 11. Phases

**P0 — Core and builtin native.** Implement registry, CLI/MCP, Evidence JSONL ledger, worker framing, errors, `proc.py`, detection, and LIEF/Capstone inspection. Test `/bin/ls` and an ELF fixture; check unsupported operations and unknown xref/diff results.

**P1 — Ghidra and JavaScript/Electron static.** Add pyghidra, ASAR inventory, tree-sitter queries, import/IPC extraction, and source maps. Golden-test rea's `website/public/examples/notes-electron`: one literal channel, renderer transmission, main handler, paired channel, zero ambiguous channels ([rea-js-web.md](research/rea-js-web.md)).

**P2 — Web, HAR, process capture, extraction.** Add loopback Playwright, strict HAR, bounded PTY capture, and safe extraction. Keep execution opt-in; test cleanup, truncation, and unknown outcomes.

**P3 — Remaining kinds and engines.** Add .NET, Android, Apple, EVM, Hopper, and LLDB. Test detection, limits, and failures for each. IDA waits in the backlog (section 12).

## 12. Resolved questions

Resolved 2026-10-10:

- Python 3.12 is the floor (`>=3.12`). CI runs 3.12 and 3.13; the Homebrew launcher runs 3.13.
- Engines follow the policy in section 6: `ENGINE_ORDER = ("ghidra", "hopper", "builtin")`, IDA only when named, never a cloud decompiler. Hopper comes first in P3; IDA waits in the backlog for a tester with an Expert or Ultimate license.
- No MCP prompts. The installed skill, `cleanroom/skill/SKILL.md`, is the only workflow guidance in v1.

## Credits

CleanRoom adapts ideas and some code from [morluto/rea](https://github.com/morluto/rea) (MIT). Adapted files keep rea's copyright notice, and a `NOTICE` file lists them.
