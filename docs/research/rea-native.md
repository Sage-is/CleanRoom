# rea survey: Native binaries: Hopper, Ghidra, IDA, lldb, pwntools, EVM

Survey notes on [morluto/rea](https://github.com/morluto/rea) (MIT) at commit `46c9cba`, written by a read-only research agent on 2026-10-10. Paths are relative to the rea repo root. Line counts and edge cases are as reported; spot-check before relying on one.

### 1. Tools and CLI commands (contracts in `src/contracts/{officialToolContracts,hopperMemoryContracts,enhancedToolContracts,functionWorkflowToolContracts}.ts`, `contracts/native/*`, `contracts/evm/*`)

**Deep-provider operations.** Inputs are `document?`, plus `address`/`procedure` (a name or 0x address).
- **Inventory**
  - `list_procedures`, `list_names`, `list_strings`, `list_segments` and `list_documents` return `[{address, value, facts?}]`.
  - `search_procedures` and `search_strings` take `{pattern, mode: literal|regex, case_sensitive}`.
- **Procedures**
  - `procedure_address`, `procedure_info` (entry, signature, locals, size, body ranges), `procedure_assembly` (string) and `procedure_pseudo_code` (string or null).
  - `procedure_callers` and `procedure_callees` return address lists. `procedure_references` takes a direction and returns typed edges.
  - `read_function_instructions` returns lines. `resolve_containing_procedure` returns found, or the reason: outside_segments vs not_in_procedure.
- **Addresses**
  - `xrefs` returns addresses. Also `address_name`, `comment`, `inline_comment`, `next_address` and `prev_address`.
  - `read_bytes {address, length=256}` returns `{bytes_hex, returned_bytes, complete}`. `address_to_file_offset` returns an offset.
- **Mutations:** `set_comment`, `set_inline_comment`, `set_address_name`, `set_addresses_names`, `set_bookmark`/`unset_bookmark`, `list_bookmarks`. Each returns a readback-matched bool.
- **GUI-only (Hopper):** `current_address`, `current_procedure`, `current_document`, `goto_address`.
- **Ghidra-only**
  - `annotate_native_function`, `inspect_native_instruction` (decoded/data/interior/outside-memory), `resolve_native_call_targets` and `inspect_native_data_type`.
  - `inspect_native_load_image` (MZ/COM digest verification).
- **Dossier:** `analyze_function` returns identity+body, pseudocode, assembly, comments, callers/callees, in/out references, referenced strings/names, basic blocks, and `native_api`/`native_value_flow` (Ghidra p-code).

**Workflows composed from the ops above:** `binary_overview`, `batch_decompile`, `get_call_graph`, `trace_call_path`, `trace_feature`, `find_xrefs_to_name`, `inspect_native_api` (jump tables), `trace_native_values` (budgets: depth 3, functions 16, nodes 5k, edges 10k), `trace_native_ui_action`, `inspect_native_dispatch_metadata`, `get_objc_classes`/`get_objc_protocols` and `analyze_swift_types`.

**macOS native** (`src/native/NativeMacOSProvider.ts`):
- Shell-outs to Apple tools: `inspect_macho`, `inspect_signature`, `inspect_plist {path?}`, `list_architectures` and `demangle_swift {symbols[]}`.
- `observe_native_calls {breakpoints[function|objc-method], arguments, environment, duration_ms ≤600k, max_events ≤100k, argument_registers ≤8, backtrace_frames ≤64}`.
- `observe_native_ui {pid, window_id}` and `capture_native_ui_scenario {steps: click|scroll|key-entry|wait}`.

**Offline, no target needed:** `inspect_binary_layout {path}`, `inspect_recorded_crash {path, include_debugger_context?}` and `inspect_evm_interface {path, encoding: raw|hex}`.

**CLI** (`src/cli/core{Binary,Native}Commands.ts`): kebab-case equivalents (analyze/inspect, decompile, function, instructions, search, xrefs, trace, read-bytes, …). Every command is a one-shot `runDirectAnalysis(path, op, params, {provider, target-format, snapshot})`: open, run, close.

### 2. How each engine is driven

**Hopper** (`src/hopper/BridgeLauncher.ts`, `bridge/hopper_bridge.py`)
- Launch: `hopper -l Mach-O|FAT|ELF|WinPE --intel-64|--aarch64… --analysis -Y bootstrap.py --executable|--database PATH`. The bootstrap sets `REA_SOCKET/TOKEN/RUN_ID/TARGET_PATH` and then runs the bridge on Hopper's own Python thread.
- Protocol: the bridge listens on an AF_UNIX socket (mode 0600) and serves NDJSON `{id, token, method, params}`. Responses are `{id, result|error}` plus progress/diagnostic events. The token is checked with `hmac.compare_digest`. The client polls for the socket every 50ms, then calls `health`.
- Timeouts: startup 120s, shutdown 30s. On macOS it first runs `open --hide --background -a` and waits 5s.
- Lifetime: on macOS the launcher forwards to the running app and exits 0, so it is an "external application". Shutdown is a `shutdown_document` request.
- Linux demo mode adds a private Xvfb, optionally inside an `unshare` user namespace (`LinuxPrivateDisplayProbe.ts`).
- A per-target lease socket stops two sessions from opening the same target (`HopperTargetLease.ts`).

**Ghidra** (`GhidraLauncher.ts:371`, `GhidraJavaLaunch.ts`, `bridge/ghidra/ReaGhidraBridge.java`)
- Launch: `java` with args from `LaunchSupport.jar -vmargs`, plus `-Xmx${GHIDRA_HEADLESS_MAXMEM||2G}`, an isolated user.home/tmpdir, and `ghidra.Ghidra AnalyzeHeadless proj rea-project -import T -readOnly -deleteProject -postScript ReaGhidraBridge.java session.json`.
- DOS inputs add `-loader MzLoader|BinaryLoader -loader-baseAddr 1000:0100 -processor "x86:LE:16:Real Mode"`. COM inputs also run a preScript (`ReaGhidraPrepareCom.java`).
- The post-script stays resident after auto-analysis and serves NDJSON over AF_UNIX, or token-authenticated 127.0.0.1 TCP on Windows.
- The handshake (`ping`) checks run_id, Ghidra version (12.1.x), profile digest and the imported program SHA-256.
- Startup deadline is 330s (`config/ghidraStartupTimeout.ts`); shutdown 10s.
- Requests are a serial FIFO. **Cancelling an active request kills the JVM**; the next query re-imports the target.
- Decompiler: one `DecompInterface` with timeout 0 (no limit). Inventories are cached in fields.

**IDA** (`src/ida/*`, `docs/ida-provider.md`)
- REA does not drive IDA directly. It is an **MCP client** of mrexodia/ida-pro-mcp, over stdio (MCP SDK) or Streamable HTTP. Upstream request timeout defaults to 300s.
- **Attached mode** (legacy 1.4 tools): binds by comparing `get_metadata.sha256` with the target, checked before and after every request.
- **Headless mode**: copies the input into a private 0700 directory, calls `idb_open {force_headless, run_auto_analysis, init_hexrays, preferred_session_id}`, injects `database` into later calls, and closes with `idb_close {save:false}`. It then checks `idb_list` to confirm the session is gone. `IDA_MCP_MAX_WORKERS=1`.

**lldb** (`LldbCallTracer.ts:394`, `bridge/native/rea_lldb_tracer.py`)
- Launch: `lldb --batch --no-lldbinit --no-use-colors -o "command script import tracer.py" -o "rea_trace cfg.json"`.
- The tracer sets `target.skip-prologue false`, uses `BreakpointCreateByName` (Auto / Selector / Full `-[C sel]` and `+[C sel]`), and auto-continues on every hit.
- It reads argument registers (arm64 x0–x7, x86_64 rdi–r9). The receiver class comes from `eDynamicDontRunTarget`, so no target code runs.
- Handshake: the process launches stopped and writes its PID; the parent verifies identity and acks; the tracer then continues.
- stdout/stderr go through FIFOs capped at 1 MiB. Observations are written to a JSONL journal so they survive a crash. The process is killed on max_events or duration; the parent deadline is duration + 60s.

**pwntools / pwndbg** (`bridge/pwntools/*`, `bridge/pwndbg/*`)
- Runs under the caller's `REA_PWNTOOLS_PYTHON -I`. Request and reply are JSON files.
- `decoder_runtime.py` lowers RLIMIT_AS to 3 GiB, CPU to 30s and FSIZE to 64 MiB. MemoryError exits 75 and EFBIG exits 76, each with a marker file.
- pwndbg: execs `gdb -nx -nh --batch -iex 'set auto-load off' -iex 'set debuginfod enabled off' -iex 'set auto-solib-add off'` and then `core-file` on a fixed relative name.

**EVM:** EVMole 0.9.3 WASM in a Node worker under `prlimit`. **Windows:** a C++ N-API addon (`native/windows`) for reparse-free path admission, private DACLs and a Job Object.

### 3. Shared operations and where providers differ
- **Common core:** the inventory ops, procedure ops, `xrefs` and `analyze_function`.
- **Hopper** adds the GUI cursor/bookmark operations and all mutations. It does not report body ranges or permissions, and its references carry no type flags.
- **Ghidra** adds typed references, body ranges, thunk/external facts, p-code value flow, instruction/data-type inspection and annotation. It is the only provider with DOS support.
- **IDA** covers 12 read-only ops (`IdaProviderCapabilities.ts`). Callers are unavailable in headless mode.
- **Provider choice:** explicit selection, or "auto" only when exactly one candidate is usable; otherwise it fails as ambiguous. There is no priority order and no fallback (`AnalysisProviderRegistry.ts:305`).

### 4. Edge cases worth keeping
- **Name vs. address:** an explicit `0x…` or `space:0x…` is always an address. Otherwise try an exact symbol name first (names like `add` and `face` are valid hex). Bare hex is used only if no symbol matches. An ambiguous name fails and lists the candidate addresses (Java `resolveProcedure`).
- **Ghidra address format:** lowercase `0x`. A non-default space is written `%XX-encoded-space:0x…`. An offset that Ghidra would truncate is rejected. DOS addresses are linear (`seg*16+off`).
- **End conventions differ:** segments use exclusive ends; function body ranges and load mappings use inclusive ends. Report body `total_bytes` and `span_bytes` separately.
- **Hopper 6.1 basic blocks:** the block end is the last instruction's address, not an exclusive end. Detect it by block ownership (`_basic_block_end`).
- **Hopper strings:**
  - The display escaping cannot be inverted, so decode the typed bytes.
  - For UTF-16, settle byte order by comparing against the display text.
  - Long literals are split into adjacent unterminated fragments.
- **Hopper names:** names over 1024 UTF-16 units are silently truncated. NUL and lone surrogates cannot cross the API. Batch renames must validate every entry before mutating any.
- **Hopper threading:** all Hopper API calls must stay on its Python thread, or it deadlocks. That is why regex search runs outside the bridge, in a worker with a 5s deadline. Results that require complete analysis fail while `backgroundProcessActive()` is true.
- **Hopper FAT64:** Hopper cannot load FAT64, so the thin slice is extracted. File offsets are slice-relative: verify with the reverse lookup, then add the slice offset, found by matching the 12-byte header (`HopperFileOffset.ts`).
- **IDA:**
  - Pagination must advance.
  - Legacy `get_function_by_address` can return an interior address, so re-resolve by name to get the entry.
  - xrefs are capped at 1000 and callees at 500; report hitting a cap as truncation.
  - Strings come from `find_regex "(?s).*"`.
- **Ghidra script transactions:** call `end(true)` before serving so that each edit gets its own transaction it can roll back. Skip entry-point pseudo-references.
- **ELF:**
  - A pwntools 4.15 / pyelftools 0.33 incompatibility means `iter_sections(type)` and `iter_segments(type)` need a subclass shim.
  - An `SHN_UNDEF` shstrndx means "no names".
  - RELR tables and SHN_XINDEX stay unresolved.
- **Cores:** accept OSABI 0 or 3 only. Read `NT_PRSTATUS` registers via `pwnlib.elf.datatypes`. SIGINFO gives a fault address only for SIGSEGV codes 1–2.
- **Mach-O:**
  - otool segment offsets are slice-relative.
  - `plutil -convert json` fails on data and date values; fall back to xml1.
  - Use `swift-demangle --compact --` so a symbol starting with `-` is not read as a flag.
  - Inspect signatures on a private, digest-verified copy.
- **lldb:** a hardened-runtime target needs the `get-task-allow` entitlement. Debugging also requires `DevToolsSecurity -enable`.
- **Size limits:** 32 MiB input and 64 MiB reply for layout and core; 4 MiB input for EVM; Ghidra p-code is capped at 3000 ops and 12k edges.

### 5. Ceremony a Python version can drop (production lines, tests excluded)
- **Ghidra transport stack, about 3.9k lines:** GhidraClient 750, ProviderClient 442, Launcher 527, Transport 178, SocketConnection 155, Wire 109, RequestQueue 183, ResponseBuffer/Router 82, SessionError 127, plus the Inventory/Function/LoadImage/Session value files (≈1150) that re-validate the bridge's own JSON. Add ~600 lines of serve/validation code in the Java bridge. pyghidra runs in-process and removes all of it.
- **Windows support for that IPC, about 1.8k lines:** `src/windows` (601) and `native/windows` C++ (1190). They exist only because Node lacks AF_UNIX-to-Java and process containment on Windows.
- **Hopper client, about 2.7k lines** around the 1.1k-line bridge: HopperClient 919, RequestQueue 406, Cleanup 387, TargetLease 277, LinuxPrivateDisplay 421. A Python replacement is roughly an 80-line NDJSON client plus `fcntl.flock`.
- **Provider routing, about 2.8k lines:** AnalysisProviderRegistry 431, Evaluation 138, Composite 148, Lazy 146, SessionProviderRouter 201, BinarySession* ≈1.7k. A dict of providers plus the "explicit or exactly one" rule replaces it.
- **Subprocess limits-and-markers protocol, about 1.4k lines:** PwntoolsDecoder 337, Failures 292, ResourceLimits 114, Evmole provider and failures 609, the Python launch shims. Import the libraries in-process, or use one `run_isolated(fn, rlimits)` helper.
- **Process ownership, about 5.3k lines** (`src/process`, including tests) plus `ProcessRunTokenReader.swift` (332). Use `start_new_session` and `os.killpg`, or psutil.
- **Triplicated capability lists:** Java `CAPABILITIES`, TS `GHIDRA_*_OPERATIONS`, and `GHIDRA_SESSION_CAPABILITIES`; for Hopper, `HOPPER_OPERATIONS`, `EXHAUSTIVE_ANALYSIS_METHODS` and `_dispatch`. Keep one registry.
- **Hand-written output schemas** in `domain/native` (≈3.1k: binaryLayout 441, recordedCrash 360, objcSwiftMetadata 480, …), plus limitation boilerplate repeated in every capability. Return plain dicts and validate only at the MCP boundary.

### 6. Python equivalents
- **Ghidra:** `pyghidra.open_program` / `program_context` (bundled with Ghidra 11.2+), with FlatProgramAPI, DecompInterface and ReferenceManager. Port the Java bridge methods 1:1 and drop the socket, descriptor and token code.
- **IDA:** idalib (`import idapro`, `ida_funcs`, `ida_hexrays`, `idautils`), one database per subprocess. Optionally keep an ida-pro-mcp client through the `mcp` SDK.
- **Hopper:** keep `hopper_bridge.py` nearly as is. The server side needs only a `socket.AF_UNIX` NDJSON client.
- **lldb:** keep `rea_lldb_tracer.py` and run it via `lldb --batch`. A subprocess avoids lldb-module/Python version mismatch.
- **Mach-O:** LIEF for slices, load commands, imports/exports, build version, chained fixups and the signature blob. `plistlib` replaces plutil. Keep `codesign -d --entitlements :-` and `swift-demangle` as subprocesses.
- **ELF layout and cores:** pwntools and pyelftools in-process (or LIEF). Use the `pwnlib.elf.datatypes` ctypes for PRSTATUS/SIGINFO. Run gdb+pwndbg as a subprocess with the same flags.
- **EVM:** `evmole` on PyPI: `contract_info(code, selectors=True, arguments=True, state_mutability=True)`.
- **Engine-free instruction fallback:** capstone.
- **Regex with a deadline:** the `regex` module's `timeout=`.
- **Native UI:** pyobjc (ApplicationServices AX, Quartz, ScreenCaptureKit), or keep `ReaNativeUI.swift`.
- **Windows:** drop the addon. Use pywin32 Job Objects only if subprocess containment is still needed.
