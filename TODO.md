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

- [ ] **Stage 0 bootstrap**: scaffold the repo until `make ci` is green [REPO] (Alexander) #stage0 #critical
  - [ ] [MANUALLY] Create the GitHub repo `Sage-is/CleanRoom` (public) with `develop` as the default branch
  - [x] [MANUALLY] `git init` and `git flow init --init -d -m master -e develop -t v`
  - [x] [WE] `git flow init --shared -f -d -m master -e develop -t v` writes the committed `.gitflow`, so a fresh clone has the `v` tag prefix
  - [ ] [WE] Makefile, `.gitignore`, `.gitattributes`, `pyproject.toml`, `uv.lock`, `.python-version` (3.12)
  - [ ] [WE] `.pre-commit-config.yaml`, `.gitleaks.toml`, `.todoscope-exclude.csv`, `.env.example`
  - [ ] [WE] `.github/workflows/ci.yml`, `release.yml`, `nightly.yml`
  - [x] [WE] LICENSE (AGPL-3.0), NOTICE, README.md, CLAUDE.md, TODO.md, `docs/design.md` updates
  - [ ] [WE] `uv lock && make install && make ci verify`; `git ls-files -i -c --exclude-standard` prints nothing
  - [ ] [WE] `make install_hooks`, then `uv run pre-commit run --all-files`
  - [ ] [MANUALLY] First commit on `develop`; push `develop` and `master`
  - [ ] [MANUALLY] GitHub: `pypi` environment (required reviewer, tag rule `v*`), `testpypi` environment; protect `master` and `develop` on `lint` and `test`
  - [ ] [WE] `gh run watch`; fix the first CI run

## TODO

- [ ] **P0 core and builtin native**: registry, CLI/MCP, Evidence, worker, lief + capstone; about 1,970 lines [CODE] (Alexander) #p0
  - [ ] [WE] P0.1 fixtures `tests/fixtures/c/{fixture,v1,v2}.c`, `tests/conftest.py`, `tests/test_budget.py`, `tests/test_notice.py`
  - [ ] [WE] P0.2 `target.py`: `Fail`, `Target`, `open_target`, `detect`, `parse_ref`
  - [ ] [WE] P0.3 `evidence.py`: `Evidence`, `canonical`, `Ledger`, `page`, JSONL export and import
  - [ ] [WE] P0.4 `proc.py` part 1: `run_limited`, `spawn_owned`, `kill_owned`
  - [ ] [WE] P0.5 `worker.py`: `serve`, `Worker`; deadline kill; a reply over 64 MiB fails `too_big`
  - [ ] [WE] P0.6 `tools.py`, `__main__.py`: verbs `open close list show xrefs evidence doctor`; commands `mcp`, `catalog`, `setup`, `version`; golden `mcp-initialize.json`
  - [ ] [WE] P0.7 `kinds/native.py` builtin: lief slices, inventories, capstone xref scan; `pseudo` fails `unsupported`
  - [ ] [WE] P0.8 `graph.py`: `trace` BFS (`max_nodes=500`), keyed `diff`
  - [ ] [WE] P0.9 `cleanroom/skill/SKILL.md` and `tests/test_p0_e2e.py`

- [ ] **Release v0.1.0**: claim `cleanroom-re` on PyPI right after P0 [RELEASE] (Alexander) #release
  - [ ] [MANUALLY] PyPI and TestPyPI pending Trusted Publisher: project `cleanroom-re`, repo `Sage-is/CleanRoom`, workflow `release.yml`, environments `pypi` and `testpypi`
  - [ ] [MANUALLY] `gh workflow run release.yml -f index=testpypi`
  - [ ] [WE] Install from TestPyPI; run `cleanroom version`
  - [ ] [MANUALLY] On `develop` with CI green: `make release` (git-release, `minor_release`, `release_finish` after `bump_release_version`)
  - [ ] [MANUALLY] Approve the `pypi` environment
  - [ ] [WE] `gh run watch`; `https://pypi.org/pypi/cleanroom-re/0.1.0/json` returns 200; `uvx --from cleanroom-re==0.1.0 cleanroom doctor`

- [ ] **Homebrew cleanroom launcher**: uv launcher in `sage-is/homebrew-apps`, after PyPI [RELEASE] (Alexander) #homebrew
  - [ ] [WE] `homebrew-apps/cleanroom`: shell launcher with `VERSION=` that answers `version` locally; else `exec uvx -q --python "${CLEANROOM_PYTHON:-3.13}" --from "cleanroom-re${CLEANROOM_EXTRAS:+[$CLEANROOM_EXTRAS]}==$VERSION" cleanroom "$@"`
  - [ ] [WE] `Formula/cleanroom.rb`: `depends_on "uv"`, sha256 of 64 zeros until released; caveats say run `cleanroom doctor` once and show `claude mcp add cleanroom -- cleanroom mcp`
  - [ ] [WE] `make check_names NAMES=cleanroom` and `make check` in the tap
  - [ ] [MANUALLY] Commit on the tap's `develop`; `make tool_release TOOL=cleanroom VERSION=0.1.0 APPLY=1`
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

- [x] **Design doc and research notes**: `docs/design.md` and `docs/research/rea-*.md` (Alexander, 2026-10-10)
  - [x] Survey of rea at commit `46c9cba`: core, native, js-web, other targets
  - [x] 12 verbs, kind modules, one Evidence type, JSON-lines workers
- [x] **Names checked**: PyPI `cleanroom-re`; command, import and formula `cleanroom`; `scripts/check_names.py` (Alexander, 2026-10-10)
- [x] **Plan approved**: AGPL-3.0-or-later, `Sage-is/CleanRoom`, engines local only (Ghidra > Hopper > builtin, IDA only when named) (Alexander, 2026-10-10)
