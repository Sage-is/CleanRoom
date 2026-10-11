# Roadmap

This file tracks active work only. The design behind it is
`docs/design.md`; the working rules are in `CLAUDE.md`.

> **Convention** — Sections below map to kanban columns. Inline source-code
> tags use the same vocabulary so items stay cross-referenced between this
> file and the codebase. `KANBAN.canvas` auto-generates from this file and
> inline tags — do not hand-edit it.
>
> | Column      | Markdown section  | Inline tag  |
> |-------------|-------------------|-------------|
> | Backlog     | `## Backlog`      |             |
> | TODO        | `## TODO`         | `# TODO:`   |
> | In Progress | `## In Progress`  | `# FIXME:`  |
> | Bugs        | `## Bugs`         | `# BUG:`    |
> | Done        | `- [x]` items / `## Done` | —   |
>
> `# DEPRECATED:` tags should be tracked as TODO items for removal at the
> stated version.

Steps are labelled [WE] (run in the CLI session) or [MANUALLY] (a person
does it). Git and gh writes were authorised for this build under the company
special case (Alexander, 2026-10-10).

## In Progress

- [ ] **Release v0.1.0**: claim `cleanroom-re` on PyPI; P0 is on `develop` with CI green, so this is the next step [RELEASE] (Alexander) #release #critical
  - [ ] [MANUALLY] PyPI and TestPyPI pending Trusted Publisher (needs a PyPI login): project `cleanroom-re`, owner `Sage-is`, repo `CleanRoom`, workflow `release.yml`, environment `pypi` (TestPyPI: `testpypi`)
  - [x] [WE] GitHub environments `pypi` (reviewer: opencoca, tag rule `v*`) and `testpypi` exist; ruleset `protect-trunks` guards `master`/`develop` on `lint` and `test` with admin bypass (2026-10-10)
  - [x] [WE] TestPyPI rehearsal skipped: the release went straight to the tag; `release.yml` keeps the `index=testpypi` dispatch for later releases
  - [x] [WE] `make minor_release && make release_finish` on green CI: tag `v0.1.0` on `481a186`, `master` updated (2026-10-11)
  - [ ] [MANUALLY] After the publisher exists, approve the `pypi` deployment on run https://github.com/Sage-is/CleanRoom/actions/runs/38099416308 (ci and build passed; publish is waiting). If it was approved too early and failed, add the publisher and re-run the failed jobs
  - [ ] [WE] `gh run watch`; `https://pypi.org/pypi/cleanroom-re/0.1.0/json` returns 200; `uvx --from cleanroom-re==0.1.0 cleanroom doctor`

## TODO
- [ ] **Homebrew cleanroom launcher**: launcher and formula are on the tap's `develop` with the zero sha256; `tool_release` waits for PyPI [RELEASE] (Alexander) #homebrew
  - [x] [WE] `homebrew-apps/cleanroom`: shell launcher with `VERSION=` that answers `version` locally; else `exec uvx -q --python "${CLEANROOM_PYTHON:-3.13}" --from "cleanroom-re${CLEANROOM_EXTRAS:+[$CLEANROOM_EXTRAS]}==$VERSION" cleanroom "$@"`
  - [x] [WE] `Formula/cleanroom.rb`: `depends_on "uv"`, sha256 of 64 zeros until released; caveats say run `cleanroom doctor` once and show `claude mcp add cleanroom -- cleanroom mcp`
  - [x] [WE] `make check_names NAMES=cleanroom` and `make check` in the tap
  - [x] [WE] Committed and pushed on the tap's `develop` (2026-10-10)
  - [ ] [MANUALLY] After PyPI has 0.1.0: `make tool_release TOOL=cleanroom VERSION=0.1.0 APPLY=1` in the tap
  - [ ] [WE] `brew test cleanroom`

- [ ] **P1 Ghidra and static JS/Electron**: pyghidra worker, ASAR, tree-sitter, IPC goldens; about 1,610 lines [CODE] (Alexander) #p1
  - [ ] [MANUALLY] Install Ghidra 12; set `GHIDRA_INSTALL_DIR` and `JAVA_HOME=/opt/homebrew/opt/openjdk@21` in `.env`
  - [ ] [WE] P1.0 spike in the scratchpad: JDK pick, startup time, `-Xmx`, stray JVM stdout, Gatekeeper `xattr`, thin-slice import, `flock`, kill then reopen
  - [ ] [WE] P1.1 `engines/ghidra_worker.py` (450): project cache under `~/.cache/cleanroom/ghidra/<sha256>/`; `info`, inventories, `pseudo`, `asm`, `bytes`, `xrefs`, `annotate`
  - [ ] [WE] P1.2 `kinds/js.py` inventory: no-follow walk, 60-line ASAR reader, `integrity.hash` checked incl. `.asar.unpacked`
  - [ ] [WE] P1.3 tree-sitter `QUERIES` per language (js, ts, tsx); iterative walk; byte to UTF-16 offset map
  - [ ] [WE] P1.4 Node resolver and source maps (design edge cases 10 and 13)
  - [ ] [WE] P1.5 goldens: `tests/fixtures/notes-electron/`, `tests/fixtures/electron-boundary/`, JS canary file
  - [ ] [MANUALLY] Release v0.2.0, then `tool_release` in the tap

- [ ] **P2 web, HAR, process capture, extraction**: playwright, strict HAR, PTY capture, safe extract; about 1,240 lines [CODE] (Alexander) #p2
  - [ ] [WE] `kinds/har.py` (120): reject duplicate keys, `parse_float=str`, HAR 1.2 jsonschema; fixture ported from rea `historicalHar.ts`, declared size 99 kept
  - [ ] [WE] `proc.py` part 2 (+150): ownership token, psutil scan failing closed, `publish()` with `O_EXCL|O_NOFOLLOW`
  - [ ] [WE] `kinds/process.py` (320): `run(argv, steps, timeout)` with ptyprocess + pyte; filesystem snapshot before and after
  - [ ] [WE] `kinds/web.py` (400): throwaway headless profile; requests, scripts, storage, screenshots; CDP attach on loopback only
  - [ ] [WE] `extract`: ZIP and ASAR via the kinds; firmware via `binwalk`/`unblob` under `run_limited` with rlimits; port rea's firmware `generate.py` and `oracle.json`
  - [ ] [WE] Tests: setsid grandchild killed; unreadable token left alone; truncation reported; no prefix digest; archive symlink not followed; existing `out_dir` fails `bad_input`
  - [ ] [MANUALLY] Release v0.3.0

- [ ] **P3 kinds, Hopper and lldb**: evm, dotnet, android, apple, Hopper bridge, lldb tracer; about 1,600 counted lines plus adapted code [CODE] (Alexander) #p3
  - [ ] [WE] `kinds/evm.py` (60): selectors via evmole; fixture from rea `evm-interface.sol`, bytecode committed with its solc version
  - [ ] [WE] `kinds/dotnet.py` (800): dnfile + dncil, signature-blob decoder, P/Invoke matching; `tests/fixtures/pe.py` ports rea's `pe.mjs`
  - [ ] [WE] `kinds/android.py` (250): androguard for manifest, classes, xrefs; `jadx` CLI for Java; ambiguous overloads rejected
  - [ ] [WE] `kinds/apple.py` (450): bundles, DMG via `hdiutil`, `codesign`, plists, dylib resolution; goldens from rea `keyed-archive/*`
  - [ ] [MANUALLY] Buy or try Hopper
  - [ ] [WE] Spike S3: demo-mode `-Y` behaviour; cancel through `shutdown_document`
  - [ ] [WE] `engines/hopper_bridge.py` adapted from rea (about 950 lines, not counted); protocol `{id, op, args, token}`; about 60 launch lines in `native.py`; probe tests with the fake Hopper document
  - [ ] [WE] lldb: `run(..., breakpoints=[...])` drives `engines/rea_lldb_tracer.py` (839 lines, copied as-is, one-shot); port `test_rea_lldb_tracer.py`
  - [ ] [MANUALLY] `make test_engines ENGINES=hopper,lldb` on the Mac
  - [ ] [MANUALLY] Release v1.0.0 once P3 is green

## Backlog

- [ ] **IDA worker**: `engines/ida_worker.py` (300) on `idalib`; needs an IDA Pro 9 Expert or Ultimate licence to test [CODE] (Alexander) #ida
  - [ ] [WE] Open a copy of the target in `~/.cache/cleanroom/ida/<sha>/` (idalib writes `.i64` next to its input)
  - [ ] [WE] Detect a local decompiler; refuse `pseudo` otherwise
  - [ ] [MANUALLY] Test on a licensed IDA Pro 9

- [ ] **Deferred v2 features**: from design section 1 [DESIGN] (Alexander) #v2
  - [ ] [WE] JS semantic IR
  - [ ] [WE] Ghidra p-code value flow and switch tables
  - [ ] [WE] Reconstruction ledger
  - [ ] [WE] mitmproxy `.mitm` captures
  - [ ] [WE] Windows

- [ ] **Nightly engines lane**: make `nightly.yml` green once engines exist [CI] (Alexander) #ci
  - [ ] [WE] `engines` job on ubuntu: Ghidra zip + setup-java 21, jadx, `playwright install chromium`; `CLEANROOM_REQUIRE_ENGINES=ghidra,jadx,playwright`
  - [ ] [WE] `live` job on macos: `pytest -m live`; `uvx --from cleanroom-re cleanroom doctor`

## Bugs

_No known bugs. Use `# BUG:` inline tags to flag defects in source._

## Done

- [x] **Stage 0 bootstrap**: repo `Sage-is/CleanRoom`, scaffold, hooks, CI green on 3.12/3.13 Ubuntu and macOS (Alexander, 2026-10-10)
  - [x] [WE] Makefile, allowlist `.gitignore`, `.gitattributes`, `pyproject.toml` (hatchling, uv), `.python-version`, pre-commit, gitleaks, `.gitflow`
  - [x] [WE] `ci.yml`, `release.yml`, `nightly.yml`; first run fixed (`setup-uv@v7`)
  - [x] [WE] LICENSE (AGPL-3.0), NOTICE, README, CLAUDE.md, design doc updates; `make ci verify` green; hooks installed
  - [x] [WE] GitHub repo created, `develop` default, environments and ruleset set; `develop` and `master` pushed
- [x] **P0 core and builtin native**: 240 tests, 2,267 of 7,000 budgeted lines; commit `45da041` (Alexander, 2026-10-11)
  - [x] [WE] `target`, `evidence`, `proc`, `worker`, `tools`, `__main__`, `kinds/native`, `graph`, `skill/SKILL.md`, e2e tests
  - [x] [WE] Registered in Claude Code user config: `claude mcp add cleanroom -s user -- uv run --directory <checkout> cleanroom mcp`
- [x] **Design doc and research notes**: `docs/design.md` and `docs/research/rea-*.md` (Alexander, 2026-10-10)
  - [x] Survey of rea at commit `46c9cba`: core, native, js-web, other targets
  - [x] 12 verbs, kind modules, one Evidence type, JSON-lines workers
- [x] **Names checked**: PyPI `cleanroom-re`; command, import and formula `cleanroom`; `scripts/check_names.py` (Alexander, 2026-10-10)
- [x] **Plan approved**: AGPL-3.0-or-later, `Sage-is/CleanRoom`, engines local only (Ghidra > Hopper > builtin, IDA only when named) (Alexander, 2026-10-10)
