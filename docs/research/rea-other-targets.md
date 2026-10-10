# rea survey: .NET, Android, firmware, Apple artifacts, process capture

Survey notes on [morluto/rea](https://github.com/morluto/rea) (MIT) at commit `46c9cba`, written by a read-only research agent on 2026-10-10. Paths are relative to the rea repo root. Line counts and edge cases are as reported; spot-check before relying on one.

Non-test TypeScript in this scope is about 36k lines: dotnet+managed 11k, artifacts+apple 12.7k, process 10.8k, android 2.8k, firmware 1.75k. Tests add about 11k more.

### 1. Tools in scope

Each CLI command is the tool name with hyphens, prefixed by `rea`, for example `rea inspect-managed-artifact`. Every tool returns an **Evidence** envelope. Its `evidence_id` is `ev_` plus the SHA-256 of the record's canonical JSON with the id removed. The envelope carries `result`, `raw_result`, `limitations` and `locations`.

**.NET**
- `inspect_managed_artifact {path?}`
  - Returns the PE/CLI classification: `runtime_family`, `implementation`, `managed_architecture`.
  - Also assembly/module identity (MVID), references, resources, custom attributes and coverage.
  - `path` is "sticky": the server remembers the last path (`server/registerManagedTools.ts`).
- `inspect_managed_members {path?}`
  - Returns every type, field, method and MemberRef with no paging.
  - Each method carries its signature with `parse_status`, `il_sha256`, `normalized_il_sha256`, exception regions, call edges and field accesses.
- `inspect_managed_native_boundaries {path?}` returns ModuleRef, ImplMap/P/Invoke declarations, native-header indicators and non-IL implementation flags.
- `compare_managed_members {left, right}` takes two Evidence records.
- `verify_managed_native_boundaries {managed_boundaries, native_observations[]}`
- `import_managed_reconstruction {static_members, decompiler, methods, notes}` is a bring-your-own ILSpy import that locks each method to sha, MVID, token, signature hash and IL hash.
- `project_managed_application_graph {managed_artifact? | managed_members? | managed_native_boundaries?}`

**Android**
- `inspect_android_package {path}`
- `search_android_classes {path, query}`
- `inspect_android_class {path, class_name}`
- `inspect_android_method {path, class_name, method_name, overload_index?}`
- `trace_android_references {path, class_name, method_name?}`
- `project_android_application_graph {inventory_evidence[]}`

**Firmware**
- `inspect_firmware_regions {path}`
- `extract_firmware {path, output_directory, range?{offset,length}, max_depth=3 (1–10), max_output_bytes, max_output_files}`

**Artifacts / Apple** (these work on the session's active target, `contracts/artifactToolContracts.ts`)
- `inspect_artifact {integrity_policy: fail|record-and-continue}` returns a content-addressed inventory graph.
- `extract_artifact {}` extracts into a temp directory that REA chooses.
- `decode_interface_builder {max_documents≤64, max_objects≤20k, max_connections≤40k}`
- `inspect_keyed_archive {path, root/pagination}`
- `inspect_asset_catalog {offset, limit}`
- `trace_dylib_resolution {roots?, architecture?}`
- `compare_artifacts {left, right}`
- `project_apple_application_graph {inventory_evidence[]}`

**Process**
- `capture_process_scenario {executable, arguments, working_directory, environment, filesystem_observation_paths, terminal, events[input|resize|signal @at_ms], timeout_ms=30000, idle_timeout_ms=30000, settle_ms=100, limits, normalization}`. The schema and defaults are in `domain/process/processScenario.ts`.
  - CLI: `rea capture-process scenario.json --json`.
- `compare_process_captures {left, right, trace_spec?, max_capture_age_ms?}`
  - CLI: `rea compare-process-captures a.json b.json [trace.json]`.

### 2. What each analysis really does

**.NET**
- REA reads PE/CLI with its own TypeScript parser. Nothing is loaded and no external tool is used.
- `ManagedPeReader.ts` maps sections and RVAs and reads the CLI header.
- `ManagedMetadataLayout.ts` reads both the `#~` and `#-` streams, heap-size flags and coded-index widths.
- `ManagedMetadataHeaps.ts` reads the string, blob and GUID heaps plus compressed integers.
- `ManagedMemberInspectorCore.ts` decodes signature blobs.
- `ManagedMethodBodyReader.ts` and `ManagedMemberInstructionDecoder.ts` handle tiny/fat method headers, the full CIL opcode table and exception clauses.
- Comparison and verification are pure functions in `domain/managed`. ILSpy is only an optional test oracle (`REA_ILSPY_CMD_PATH`).

**Android**
- REA is an MCP client of JADX.
- It spawns `java` in single-file source mode on `bridge/android/ReaJadxBridge.java` (256 lines), with the user's `jadx-headless-mcp-0.7.1-all.jar` on the classpath.
- The bridge hosts upstream's Kotlin MCP tools over stdio, removes all but 8 of them, and narrows `list_classes`, `get_class_summary` (raw nodes, no code loading), `get_method_body` and `get_xrefs_*`. It adds `rea_jvm_status`.
- `android/JadxSession.ts` checks the server and engine identity, calls `load_apk` with `threads: 1`, then makes the per-operation calls.
- Class search pages through all names 4096 at a time and filters them in TypeScript.

**Firmware**
- REA shells out under `prlimit --as=1GiB --fsize --core=0 --cpu=120`.
- Region scan: `binwalk --quiet --search-all --threads 1 --log report.json`.
- Extraction: `unblob --process-num 1 --depth N --randomness-depth 0 --report --log --extract-dir`.
- `FirmwareReports.ts` parses the JSON reports. `FirmwarePublication.ts` publishes the output safely.

**Artifacts**
- ZIP uses `@zip.js`; ASAR uses `@electron/asar` plus integrity checks; DMG uses `/usr/bin/hdiutil` (verify, then `attach -readonly -nobrowse -mountroot`, `info -plist`, `detach`); directories are walked directly.
- Mach-O load commands and NIBArchive are hand-parsed.
- Plists use the npm `plist` package.
- `Assets.car` is read with `/usr/bin/assetutil --info`, so it works on macOS only.
- dyld resolution is modelled in `domain/apple/dylibResolution.ts` (676 lines).
- The Apple and Android "graph" projections are path-convention classifiers over inventory Evidence. They parse nothing.

**Process capture**
- The terminal is `@lydell/node-pty` (TERM `xterm-256color`), rendered with `@xterm/headless` and the serialize addon (`capture/TerminalRenderer.ts`).
- Process sampling runs `ps -axo pid,ppid,pgid,sess,command` every 50 ms.
- Filesystem snapshots use `lstat` and hash files in 64 KiB chunks.
- Comparison and the trace-spec partial-order checker are pure functions in `domain/process`.

### 3. Process ownership: the problem and the minimal version

**The problem.** REA must kill everything a target or provider spawned, including daemonised or `setsid` children, without ever signalling an unrelated process. Two things make that hard:
- PIDs and process groups get reused.
- macOS withholds the environment of some processes.

**REA's model** (`ProcessOwnership.ts`, `ProcessOwnershipObservation.ts`, `DarwinProcessRunTokenReader.ts`, plus 332 lines of Swift in `bridge/process/*.swift` compiled through `xcrun swiftc` at runtime):
- Each child is spawned detached or `setsid`, so its pgid equals its pid, and gets the environment variable `REA_PROCESS_RUN_ID=<uuid>`.
- Before launch, REA records a baseline of `{pid: start-time}`. On Linux the start time is field 22 of `/proc/pid/stat`; on macOS it is `kp_proc.p_starttime` via sysctl.
- **Cleanup:**
  1. List all processes.
  2. Build the candidate groups: the leader's group, groups of the leader's descendants, groups seen in the 50 ms samples, and any process carrying the token.
  3. Skip processes whose identity matches the baseline.
  4. Read each candidate's token: `/proc/pid/environ` on Linux, `KERN_PROCARGS2` on macOS.
  5. Check the launcher's command and parent pid.
  6. Immediately before each `killpg(SIGKILL)`, re-list and re-verify the group.
  7. Afterwards, poll for up to 1 s at 25 ms intervals until no process carries the token.
- **Fail-closed rule:** a related process with an unreadable token blocks cleanup. An unrelated one whose environment the OS withheld (foreign uid, or an Apple platform binary) is recorded under `unverified_processes` and left alone.
- **Settlement** (`ProcessCaptureLifecycle.ts:597`): poll every 50 ms until two consecutive "empty" observations, giving `quiesced`, `alive_at_deadline` or `unverifiable`.
- **Timeouts:** a 20 ms tick enforces `timeout_ms`, `idle_timeout_ms` and cancellation with SIGKILL. It keeps the reason that started the kill, because the kill otherwise shows up as an ordinary exit.

**Minimal Python version** (about 150 lines; it keeps correctness):
- Spawn with `start_new_session=True` and the env token.
- Take the baseline as `{p.pid: p.create_time()}`.
- Scan with `psutil.process_iter()`, skipping baseline-identical processes:
  - `environ()` matches the token → owned.
  - `AccessDenied` and the process is related (descendant, same pgid, or a sampled pgid) → fail closed.
  - `AccessDenied` and unrelated → record as unverified.
  - `NoSuchProcess` → gone.
- Use `os.killpg` only when every member of the group is verified. Otherwise kill verified processes one by one with `psutil.Process.kill()`, which already guards against PID reuse via `create_time`.
- Repeat until the scan comes back empty or 1 s passes. Retry token reads 3× at 40 ms to cover exec transitions.
- This removes the Swift helper, `xcrun`, the `ps` parsing and the Windows Job Object path.

### 4. Edge cases worth keeping

**.NET**
- Classification rules:
  - ILONLY clear → mixed C++/CLI.
  - A ReadyToRun header signature → modern .NET.
  - An `UnityEngine` AssemblyRef → Unity.
  - The `TargetFrameworkAttribute` prefix (`.NETFramework,` / `.NETCoreApp,` / `.NETStandard,`) decides the framework.
  - Managed architecture comes from the PE machine plus flags 0x2 and 0x20000.
- GUIDs are kept as exact little-endian text with no RFC 4122 validation.
- Tokens are build-local. Matching uses unique-only tiers: exact CIL+signature, then (declared type, name, raw signature), then structural shape. Duplicates stay ambiguous, and undecoded signatures make a member `unknown` rather than added or removed.
- **The normalized IL hash must match JavaScript formatting.** It is `JSON.stringify` of `[opcode, kind, operand]` tuples, so floats use JS `String()`: `-0`→`"0"`, `1.0`→`"1"`, `Infinity`/`NaN` spelled that way. `switch` contributes only its case count; branches contribute their absolute target offset. The hash is null unless the whole body decodes. Test vector: `nop; ret` → `5e5fad77…`.
- Exception clauses are checked: flags in {0,1,2,4}, ranges inside the IL, aligned to instruction boundaries, and filter before handler.
- P/Invoke matching:
  - exact name and module → verified;
  - the `A`/`W`/`_x`/`_x@0` name variants → inferred;
  - module mismatch → contradicted;
  - module names are compared after stripping the extension, the `lib` prefix and the Mach-O leading `_`.
- The file is re-hashed before every operation and fails if its digest changed after open.

**Android**
- Ambiguous overloads are rejected, never "first match". Method xrefs and the smali fallback cannot select an overload, so overloaded methods are reported as unsupported.
- The APK is copied into a private, immutable snapshot. One serialized session is reused, keyed by APK digest, JAR digest and JVM config, and retired after 60 s idle.
- Limits: 8 MiB per frame, 32 MiB per operation, 1 MiB of text, 120 s per operation and 90 s per decompile.
- A JRE without `jdk.compiler` cannot run the source-mode bridge. An `.aab` is not an APK.

**Firmware**
- Input must be a nonempty regular file of at most 128 MiB, opened with `O_NOFOLLOW`, copied, and set to mode 0400. A selected range becomes its own file, and only depth-0 chunks get a `root_file_range`.
- REA checks that unblob's root hash equals the snapshot hash. Exit code 1 with no diagnostics is treated as an error.
- Unblob's task graph is unordered, so it is resolved by path and blob id. Logical paths use `$input` and `$output`.
- Publication:
  - writes use `O_EXCL|O_NOFOLLOW`, with fsync and a digest readback;
  - failed output is rolled back;
  - symlinks and special files are recorded but not published.
- REA never retries with `--no-sandbox`. Version banners are checked.
- If cleanup cannot be confirmed, the workspace is kept and the provider instance is blocked.

**Artifacts / Apple**
- Formats are classified from magic bytes, not suffixes: the ZIP signature, the ASAR pickle header, `xar!`, and the `koly` trailer 512 bytes from the end.
- ZIP names that differ only in case are kept. ASAR "unpacked" files are still integrity-checked.
- During DMG cleanup, an unknown attach state is treated as attached.
- dyld modelling:
  - `@executable_path` is per process root; `@loader_path` is per image;
  - `@rpath` uses the rpath stack from the loader up to the root;
  - each image loads once per install name;
  - lazy loads are not traversed;
  - graded architectures: `x86_64h` also loads `x86_64`, but `arm64e` does not load `arm64`;
  - the `dylib_use_command` marker is 0x1a741800 with `nameoff` 28;
  - symlink escapes are reported, absolute system paths stay "undetermined" (shared cache), and "conditional" resolution is preserved.
- AppleDouble files (`._*`, `__MACOSX`) are excluded. A versioned framework with more than one version gets a null `Info.plist`.

**Process capture**
- Sensitive input is stored only as a byte count.
- A raw chunk that does not fit the budget is dropped whole, though a later smaller chunk can still fit. Rendered-frame and file-hash budgets are independent, and the file-hash budget restarts at each checkpoint.
- A file that cannot be fully hashed gets a null digest plus a reason, never a prefix hash. dev/ino/size/mtime/ctime are checked around each hash.
- Created or deleted is claimed only when enumeration of that root was exhausted.
- Port normalization handles a sentence-ending period and is applied per chunk. Custom patterns are literal (no `$&` expansion). Trailing spaces are trimmed from rendered lines.
- Comparison requires the same contract: working directory, environment, observation paths, terminal, events, limits and normalization. The executable and arguments may differ.
- Events not dispatched before exit are recorded as `target_exited`.
- On macOS, Node's `process.title` (npm sets it) wipes the env token. That residual is reported, not killed.
- Environment keys cannot contain `=` or NUL.

### 5. Ceremony a Python version can drop

- **Ports, services and registration (about 1.6k lines).** Thin pass-throughs:
  - `application/{managed 427, android 106, firmware 69, apple 27, process 272}`;
  - `server/registerManagedWorkflowTools/*` (428 lines across 7 files);
  - `registerAndroidTools.ts` (64 lines, the same `registerTool` block 5×) and `registerFirmwareTools.ts` (47).

  Replace with one decorator that turns a typed function into both an MCP tool and a CLI subcommand.
- **Schemas declared twice (about 3k lines).** zod schemas in `domain/managed/managedArtifact.ts` (493), `domain/process/processCapture.ts` (675, including partial-observation duplicates), `contracts/managed/*` (599) and `toolOutputSchemaGroups.ts` (526). Use pydantic models once.
- **JavaScript-number workarounds (265 lines).** `PlistNumberLiterals.ts` (174) and `plistNumbers.ts` (91) exist because JS loses integers above 2^53. Python's `plistlib` gives exact ints and `UID` natively.
- **Process supervision (about 2.9k → about 250 lines).**
  - `ProcessOwnership*` (about 1.6k).
  - The Darwin token reader (375 TS + 332 Swift).
  - `ProviderProcess` (549), `OwnedCommand` (213), `ExecFileOutput` (175), `ProviderDeadline` (115), `PendingOperations` (86).
  - `WindowsAuthority` (86) and Job Objects.

  Use psutil plus `subprocess.run(timeout=, start_new_session=True)`.
- **`InterfaceBuilderDecodeBudget.ts` (305 lines)** reserves bytes before allocation. A simple object/byte counter is enough.
- **Test-only byte builders stay in tests:** `ManagedPe.fixture.ts` (916), the Mach-O fixture (178), the NIB fixture (94).

### 6. Suggested Python equivalents

| Area | Suggestion | Notes |
| --- | --- | --- |
| .NET | `dnfile` (tables, heaps, coded indexes) + `dncil` (method bodies, opcodes, EH clauses) | Add a signature-blob decoder of about 150 lines. Estimate about 800 lines in total, with a P/Invoke matcher of about 100. Optional `ilspycmd` via subprocess. |
| Android | `androguard` for manifest (AXML), classes, members and xrefs, with no JVM | Use the `jadx` CLI (`--single-class`) only for method source. Or keep JADX through the Python `mcp` client, but the Java bridge is needed for overload stability and code-load-free class summaries. |
| Firmware | `binwalk` / `unblob` subprocesses with a `preexec_fn` that calls `resource.setrlimit(RLIMIT_AS, RLIMIT_CPU, RLIMIT_CORE, RLIMIT_FSIZE)` | Drops the util-linux `prlimit` dependency. Unblob is itself Python, but keep it out of process for its sandbox. |
| Archives | `zipfile`; ASAR in about 60 lines (pickle header + JSON); `hdiutil` via subprocess | |
| Apple | `plistlib` (binary plists, NSKeyedArchiver UIDs); `lief` or `macholib` for Mach-O | Hand-roll `dylib_use_command` with `struct` if the library lacks it. NIBArchive is about 120 lines of `struct` + varint. Keep `assetutil` via subprocess. |
| Process capture | `ptyprocess` (spawn, `setwinsize`, `kill`) or `pexpect`; `pyte` as the headless VT renderer; `psutil` for the process table, `environ()`, `create_time()` and `uids()`; `os.killpg` | `pyte` has no equivalent of xterm's serialize addon, so `serialized_state` will not be byte-compatible with captures made by the TypeScript version. |
