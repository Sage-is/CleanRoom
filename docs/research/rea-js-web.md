# rea survey: JavaScript, Electron and web

Survey notes on [morluto/rea](https://github.com/morluto/rea) (MIT) at commit `46c9cba`, written by a read-only research agent on 2026-10-10. Paths are relative to the rea repo root. Line counts and edge cases are as reported; spot-check before relying on one.

Helper agents covered the browser side and semantic tracing; the main survey spot-checked their claims.

Scope size is about 72.9k TS lines, about 19k of them tests:

| Directory | Lines |
|---|---|
| `src/domain/javascript` | 34.5k (24.9k non-test) |
| `src/browser` | 20.3k (15.6k non-test) |
| `src/application/javascript` | 14.1k |
| `src/javascript` | 2.6k |
| contracts + artifacts | 1.3k |

### 1. Tools (CLI name = MCP name with hyphens)

**Static tools (nothing is executed):**
- **`analyze_javascript_application`** `{input_path (absolute), format auto|asar|directory, integrity_policy fail|record-and-continue}`. Also reachable as `rea analyze <dir|.asar>`.
  - Returns an Evidence record with: the JS Application Graph (JAG), `semantic_graph`, `electron_summary` (IPC counts: paired, ambiguous), statistics, `integrity_contradictions`, limitations.
  - JAG vocabulary: 32 node kinds (`javascriptApplicationGraphSchemas.ts:15`) and 12 relations (contains/loads/imports/maps_to/exposes/sends/invokes/handles/calls/persists_to/observed_as/changed_from).
  - Entry point: `src/application/javascript/JavaScriptArtifactReconstruction.ts`.
- **`recover_javascript_sources`** `{path, output_directory (must not exist), extraction_mode structural|heuristic|inspection, rewrite_level minimal|standard|aggressive}`. Writes `inputs/bundle.js`, `modules/`, `reports/` and `manifest.json`, and returns an `analysis_input` ready for the tool above.
- **`trace_application_feature`** `{application Evidence, seed node-id|route|string|api|channel|module|native-export, direction}`. A BFS over the JAG; returns the reachable subgraph, terminal paths and native handoffs.
- **`trace_javascript_semantics`** `{application, query{seed, direction backward-provenance|forward-influence|callers|ownership, allowed_relations, include_ambiguous_dynamic_edges}}`. Returns the full-closure BFS over the semantic graph. It never re-parses.
- **`compare_application_versions`** `{left, right}`. Matches entities by tiers, admitting only unique matches: content digest, then module-source digest, node id, source-map identity, structural fingerprint, semantic key. "Added" or "removed" is reported only when the other side's coverage is complete.
- **`compare_source_to_bundle`** `{reference: HistoricalSourceGraph (from the import-reference-source CLI command, git or dir), application}`.
  - Classifies each source file as unchanged, modified, removed, split, merged, duplicated or unknown.
  - Signal weights (`sourceToBundleComparisonSchemas.ts:13`): exact digest 100, map original path 70, exact path 60, suffix 40, basename 20, extension 5.
  - Basename or extension alone never forces a match.
- **`compare_javascript_export_shapes`** `{left, right, {left,right}_module_path, {left,right}_export_name}`. Returns JSON-Pointer diffs of return shapes computed at analyze time. Variants pair only by reciprocal unique literal discriminants.
- **`reconcile_javascript_runtime`** `{static_layers[{role, analysis, runtime_mappings file-root|url-prefix}], runtime_observations[]}`. Returns the JAG plus `observed_as` edges and load states.
  - With captured bytes: digest match is "high", several matches are "ambiguous".
  - Without bytes: a match by location alone is "medium".

**Browser tools.** All need a loopback CDP endpoint (`http://127.0.0.1:PORT/` only):
- `list_browser_targets`
- `inspect_web_page`: DOMSnapshot, accessibility tree, scripts, network, storage; heavy parts are opt-in flags.
- `analyze_web_bundle`: captured scripts go through the same Babel static pass, with optional source-map fetch.
- `observe_web_session`
- `observe_web_execution`: Profiler precise coverage.
- `inspect_web_event_listeners`
- `discover_webmcp_tools`
- `capture_web_screenshot` / `compare_web_screenshots`
- `compare_web_captures`: 8 dimensions; incomplete capture gives "unknown".
- `capture_browser_scenario`
- `inspect_web_network_capture`: HAR or mitmproxy file.
- `export_web_scripts`, `trace_web_module_imports`, `trace_web_source_location`
- `list_electron_targets` / `inspect_electron_page` (`file://` pages only), `capture_electron_scenario`
- `list_javascript_runtime_targets` / `observe_javascript_runtime`: Node `--inspect`; `scriptParsed` and context events only.

### 2. Static pipeline: what actually runs
1. **Inventory.**
   - Directory walk without following symlinks, or ASAR via `@electron/asar` `getRawHeader`/`listPackage` (`src/artifacts/AsarArtifactReader.ts`, 518 lines).
   - Each entry's SHA-256 is checked against the header's `integrity.hash`. Only the whole-file hash is checked; block hashes are ignored.
   - The `.asar.unpacked` companion is read too. Nested ASARs are recursed into unless their hash mismatches.
2. **Parse.** Each file is parsed once with `@babel/parser` 8 (`javascriptSourceParser.ts`, 57 lines).
   - Options: `sourceType: "unambiguous"`, `errorRecovery`, no comment attachment.
   - Plugins: `decorators-legacy` and `typescript` always (`dts` for `.d.*ts`); `jsx` except for plain `.ts/.mts/.cts`.
   - No `@babel/traverse` or Babel scope: there is a hand-rolled walk and a custom scope resolver.
3. **One visitor per file** (`javascriptStaticAnalysis*.ts`) collects:
   - **References:** import and export-from, `import()`, `require` / `x.require`, `__webpack_require__(id)` and its `.bind`, `__webpack_require__.e` (recorded as `chunk:`), `new Worker`, `serviceWorker.register`, and the Vite `__vite__mapDeps` table (found by regex).
   - **Bundle modules (recognition only):** `*webpackChunk*.push([[ids],{key:factory},runtime])` for webpack/Rspack, and esbuild `__commonJS`/`__esm({...})`.
     - Each factory becomes a module with a source-slice SHA, a rename-resistant `babel-ast-v1` token fingerprint, and its CommonJS export names.
     - No browserify, Parcel, `System.register` or bare `__webpack_modules__`.
     - Actually splitting a bundle into files is Wakaru's job.
   - **Other facts:** endpoints, storage, routes (`route`/`addRoute`/`useRoutes`/`createBrowserRouter` and `path:` props), 10 vendor substrings, `sourceMappingURL` comments.
   - **Electron:**
     - BrowserWindow `webPreferences`, explicit values only.
     - Preload paths from static path evaluation of `path.join`/`resolve`, `__dirname` and `fileURLToPath(new URL(x, import.meta.url))`.
     - contextBridge keys.
     - `ipcRenderer` send/sendSync/invoke/postMessage/sendToHost/on/once and `ipcMain` on/once/handle/handleOnce, with literal or dynamic channels.
     - `senderFrame.url/origin` comparisons, kept as "validation candidates" only.
     - `utilityProcess.fork`.
     - Requires of `*.node` files.
4. **Source maps in the static path.**
   - Only the JSON is read: `sources`, `sourceRoot`, and SHA-256 of `sourcesContent`. Index maps are flattened. Mappings are never decoded.
   - Source names map to artifact paths (`javascriptSourceMapPaths.ts`): relative names are artifact-relative; absolute and `webpack://` names use suffix matching.
   - VLQ decoding happens only in `trace_web_source_location` (`@jridgewell/trace-mapping` in a child Node process).
5. **Graph.**
   - **Process roles:** package.json `main` → main; `renderer`/`browser`/`module` → renderer; `loadFile`/`loadURL` → renderer; webPreferences `preload` → preload; `utilityProcess.fork` → utility. Roles come from entry points and are not propagated along imports.
   - **Imports:** resolved by a full Node resolver (`JavaScriptArtifactPathResolution.ts`, about 700 lines). HTML `<script>` and `<base>` are handled with parse5.
   - **IPC pairing:** an edge only for a literal channel with exactly one compatible handler (invoke ↔ handle/handleOnce, send ↔ on/once). Otherwise ambiguous or unpaired, with no edge.
   - **Native add-ons:** a `.node` require resolved to an inventoried file becomes a `native-addon` node. Requested member names are not verified as exports.
6. **Semantic graph** (from the same parse):
   - 24 node kinds and 44 relations, built on a value lattice of literal, union, object, array and unknown.
   - Limits: 256 candidates, 1 MiB, depth 256; 100k nodes in total, 20k per file.
7. **IDs and Evidence.** Every ID is SHA-256 of RFC 8785 canonical JSON. Evidence is kept per session, so follow-up tools accept inline Evidence or `{kind: "retained-evidence", evidence_id}`.

**Wakaru.**
- The `third_party/wakaru` submodule (pinned `6070266`, v1.13.0) is audit-only. It is never built or imported, and it is empty in this clone.
- At runtime rea runs the caller-supplied release binary from `REA_WAKARU_COMMAND`. CI downloads `wakaru-linux-x64.tar.gz` with sha256 `e8c7ca05…`.
- It runs under `prlimit --as=1GiB --fsize=128MiB --cpu=120 --core=0` with `RAYON_NUM_THREADS=1`.
- Sequence (`src/javascript/recovery/WakaruExecution.ts`):
  1. `wakaru --version` must print exactly `wakaru 1.13.0`.
  2. `wakaru SRC --unpack=strict|auto|inspect --level=L --provenance --emit-source-map --json -o staging`.
  3. Exit 0 is success, exit 1 is partial.
  4. Parse the stdout report and `provenance.json`, whose ranges are UTF-8 byte offsets.
- Gated to Linux x64.

### 3. Browser side
- **Passive tools use raw CDP over `ws`** (`CdpConnection.ts`, 363 lines; `CdpTargetSession.ts` uses flat sessions).
  - Domains: Page, Runtime, Debugger (`scriptParsed`/`getScriptSource`), Network, DOMSnapshot, Accessibility, DOMStorage, IndexedDB, CacheStorage, Profiler precise coverage, DOMDebugger, Emulation, WebMCP.
  - The tools never launch Chrome. `BrowserProcessStartup.ts` is used only by `scripts/`; the user must already be running Chrome with a debugging port.
- **playwright-core 1.58.2 is used only for active work:**
  - Scenarios: `launchPersistentContext` on a mode-0700 temp profile, or `connectOverCDP`. The environment is allowlisted, service workers are blocked, downloads are off.
  - Electron active: `_electron.launch` with `-r scripts/electron-active-hook.cjs` (673 lines, monkey-patches `ipcMain` and `webContents`).
  - Module tracing: Chromium `import.meta.resolve`.
- **WebMCP:** `WebMCP.enable`, then wait for the `toolsAdded`/`toolsRemoved` replay that arrives after the enable reply. It never calls `invokeTool` and never touches `navigator.modelContext`.
- **HAR:** strict UTF-8, duplicate keys rejected, number lexemes kept exactly (lossless-json), validated with ajv against `har-schema` 2.0.0, HAR 1.2 only. Runs in a child Node process with a 192 MB heap.
- **mitmproxy:** `mitmdump` 12.2.3 with `-s bridge/mitmproxy/capture.py`, which is already Python and reads tnetstring.
- **Redaction:**
  - Nulled: authorization, proxy-authorization, cookie and set-cookie headers, and HAR cookie values.
  - Stripped: URL userinfo.
  - Caller-supplied secrets are matched raw, URI-encoded, form-encoded and JSON-escaped.

### 4. Edge cases worth keeping
- **Offsets.** Babel offsets are UTF-16 code units, and a BOM counts as one unit. Wakaru uses UTF-8 bytes. Python strings index by code point and tree-sitter by bytes, so convert explicitly. Line terminators: CRLF, LF, CR, U+2028, U+2029.
- **`sourceMappingURL`.** Comment-only scan for `//#` or `//@`; every directive is kept. Use non-backtracking scans: large inline data URLs blow regex stacks.
- **Source-map source names.**
  - `sourceRoot` is joined with "/".
  - Reject `%2f`/`%5c`, paths escaping the root, bad UNC hosts and directories.
  - Windows drive paths are supported.
- **Node resolver.**
  - `exports` fallback arrays; conditions include `module-sync`.
  - Targets must start with `./` and contain no `..` or `node_modules` segments, including encoded forms.
  - ESM paths are percent-decoded once; CommonJS paths stay literal.
  - A missing exports target does not fall back to `index`.
  - Inventory paths are compared after NFD → NFC normalization.
  - Never resolve across nested-ASAR boundaries.
  - Prefix-only builtins are distinguished from packages.
- **URI schemes.** `web3:app.js` is external; `./web3:app.js` is local.
- **HTML.**
  - Strip whitespace, tabs and newlines from `src` and `href`; reject encoded separators and NUL.
  - A query-only reference resolves to the document itself.
  - Source ranges must handle CR-only line endings.
- **Electron.**
  - Never substitute Electron's defaults for omitted `webPreferences`.
  - Dynamic channels are never paired.
  - Endpoints keep query and fragment; only userinfo is removed.
- **Unknown is not absent.** Truncation gives "unavailable", never a prefix. Coverage "partial" blocks removed/added claims.
- **Values.** -0, NaN and Infinity become unknown. Chains 12k deep must not overflow, so evaluation must be iterative (Python's recursion limit makes this mandatory).
- **Safety fixture.** A webpack fixture throws if executed; analysis must never run code.
- **CDP behaviour.**
  - A redirect reuses the same `requestId`.
  - Error -32000 means that body is unavailable; -32601 means the domain is unavailable.
  - A navigation during capture fails the capture.
  - Source-map fetch follows only 301/302/303/307/308, within allowed origins, without credentials.
  - Never send `Runtime.runIfWaitingForDebugger`.
  - Node `/json/list` reports `file://` paths unencoded, with `\` and `"` replaced by `_`.

### 5. Ceremony a Python port can drop
**Why 140 domain files:** 45 semantic files (17 of them tests), 12 reconciliation files (3.1k lines around a decision tree of about 130 lines), 7 version-comparison files, 7 export-shape files, 9 static-analysis files and 9 Electron files. Tests and fixtures account for about 9.7k of the domain lines.

**The same data declared three or four times:**
- Domain zod schemas: 2.4k lines.
- Contracts pick `.shape.x` "facts" from them and re-wrap with an `evidenceInputSchema` union (`src/contracts/javascript/applicationWorkflowInputContracts.ts`).
- Example payloads: 656 lines.
- CLI flag files.

**Semantic graph layering:** the IR feeds 8 per-family projection files (1.8k lines), which only map records to nodes and edges. About 465 lines (`javascriptSemanticGraph.ts:216–680`) re-validate a graph built moments earlier in the same process.

**Port, Service and Evidence triples** (1.7k lines in the application layer), each with exactly one implementation.
- Wakaru is about 1.2k lines across register/contract/CLI/Service/Port/Provider/Command/Execution/Report/Publication for what is one subprocess call plus two JSON parses.

**Child processes that exist only to cap V8 memory:**
- Source-map tracer: 471 lines (`SourceMapCommand`, `CodecProcess`, `Protocol`, `Decoder`).
- HAR decoder: about 340 lines.

**Dead code:**
- Counters named `omitted*` are always zero.
- `semanticFamilyStatus` never returns "complete".
- `BrowserProcessStartup.ts` is unused in `src/`.
- Three near-identical `runBrowserTool`/`runElectronTool`/`runRuntimeTool` wrappers.

### 6. Python equivalents
- **Parser**, the one real decision:
  - **tree-sitter-javascript / -typescript / -tsx:** pure wheels, tolerant of errors. Its queries fit the static extractors (imports, IPC, BrowserWindow, webpack tables) well. The cost: fingerprints are not compatible with rea's `babel-ast-v1`, and string cooking and -0 handling must be re-derived.
  - **Node sidecar running `@babel/parser`** with the same options, emitting a JSON AST: needed only if exact Babel parity matters, chiefly for semantic tracing.
  - Do not use esprima-python: it has no TS or JSX.
- **ASAR:** about 60 lines by hand. Header layout: uint32 4, uint32 header size, then pickle (uint32, uint32 length, JSON); file data starts at 8 + header size. Read `integrity.hash` and the `.unpacked` companion.
- **Source maps:** write a small VLQ decoder plus index-map `sections` handling. rea needs every segment at an equal position and checks for overlapping sections, which libraries hide. `sourcemap` / `symbolic` work as fallbacks.
- **Node resolver:** no adequate Python library; port it (about 300 lines).
- **HTML:** stdlib `html.parser` with `getpos()` is enough for script and base tags. Apply the URL whitespace rules by hand.
- **Canonical JSON:** the `rfc8785` package, then hashlib. Evidence store: a dict keyed by `evidence_id`.
- **Wakaru:** shell out to the same release binary using `resource.setrlimit` in `preexec_fn` instead of `prlimit`. Unverified: whether Wakaru 1.13.0 ships macOS binaries, which would let the Linux-only gate go.
- **CDP:** a `websockets` client with an id map, about 100 lines.
- **Scenarios:** playwright-python (`launch_persistent_context`, `connect_over_cdp`).
- **Electron active:** playwright-python has no `_electron`. Spawn Electron with `--remote-debugging-port=0` and `-r hook.cjs` and use raw CDP. Keep the hook in JS, since it runs inside Electron.
- **HAR:** `jsonschema` with the har-schema JSON files, `object_pairs_hook` to reject duplicate keys, `parse_float=str` to keep lexemes. haralyzer adds nothing.
- **mitmproxy:** import `mitmproxy.io` directly in-process.
- **PNG diff:** Pillow.
- **Golden fixture:** `website/public/examples/notes-electron/` (6 files). Expected IPC summary: 1 literal channel, 1 renderer transmission, 1 main handler, 1 paired, 0 ambiguous.
