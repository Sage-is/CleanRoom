---
name: cleanroom
description: Use when asked to inspect, explain or compare a local binary, app bundle, JavaScript or Electron app, APK, .NET assembly, firmware image, HAR capture or web page and the answer must rest on cited evidence rather than guesses.
---
<!-- Adapted from rea .agents/skills/reverse-engineer-anything/SKILL.md@46c9cba (MIT, (c) morluto); see NOTICE -->
<!-- rea is MIT licensed, Copyright (c) 2026 morluto; the licence text is in NOTICE. -->

# CleanRoom

CleanRoom reverse-engineers a local target and records every result as Evidence.
The 12 verbs are MCP tools and `cleanroom` CLI subcommands alike. Every engine
is local; there is never a cloud decompiler.

## Before the first call

- If no target is named, ask which app, file or URL to inspect. Resolve a
  human-readable name to one installed artifact when the workspace makes it
  clear; ask only when several match. Never pick an example app yourself.
- Run `doctor` once per session for the engines and kinds present and what to install.
- One target is open at a time; `open` replaces it, `close` releases it, Evidence stays.
- Work summary-first: `open`, then one `list`, then read the items and ids
  before calling anything else. Follow up only when the reply leaves a specific
  question open, and prefer `match` and `show` over paging through everything.
  Never repeat an identical call; `evidence(id)` returns the reply again.

## Verbs

| Verb | Arguments | Use |
|---|---|---|
| `open` | `path`, `kind?`, `engine?`, `arch?` | Detect and bind a file, directory or URL. `arch` picks a FAT slice; `kind` forces detection (`evm` needs it). |
| `close` | | Release the target and its workers. |
| `list` | `what`, `match?`, `offset=0`, `limit=200` | Inventory one category; the `open` reply names the categories under `list`. `match` is a substring or `/regex/`. |
| `show` | `ref`, `view=auto` | One item. The `open` reply names the views under `views`. |
| `xrefs` | `ref`, `direction=both` | References into (`to`), out of (`from`) or both ways. |
| `trace` | `start`, `goal?`, `depth=3`, `max_nodes=500` | Breadth-first walk over `xrefs`, optionally until `goal`. |
| `diff` | `a`, `b`, `what?` | Keyed comparison of two targets' `list` output: added, removed, changed, unknown. |
| `extract` | `target`, `out_dir` | Unpack an archive, bundle, image or JS bundle into a new directory. |
| `run` | `argv` or `url`, `steps?`, `timeout=30` | Capture one bounded execution. The only verb that runs the target. |
| `annotate` | `ref`, `name?`, `comment?` | Rename or comment an item in a native engine's database. |
| `evidence` | `id?`, `offset?`, `limit?`, `export?`, `import?` | Re-page a record, list the ledger, export or import JSONL. |
| `doctor` | | Engines, libraries, kinds, verbs, ledger and cache paths. |

CLI form: `cleanroom -t PATH list functions --limit 50`; `-t` opens the target
before the verb, `cleanroom open PATH` alone reports identity, and global options
(`-t`, `--kind`, `--engine`, `--arch`, `--ledger`) precede the verb. MCP form:
tool `list` with `{"what": "functions", "limit": 50}`.

## Route by target kind

| Target | First calls |
|---|---|
| Native executable or library (ELF, Mach-O, PE) | `open`, `list functions` or `list strings --match TEXT`, `show REF --view asm` (or `pseudo` with a decompiler), `xrefs REF --direction to`, `trace` |
| App bundle, DMG or IPA | `open`, `list files`, `list dylibs`, `list entitlements`, `show` a plist, then `open` the main executable |
| JavaScript or Electron app (tree or ASAR) | `open`, `list modules`, `list channels`, `list endpoints`, `show MODULE`, `xrefs`, `extract` when files are needed |
| Android APK | `open`, `list permissions`, `list components`, `list classes --match NAME`, `show CLASS --view java`, `xrefs` |
| .NET assembly | `open`, `list types`, `list pinvokes`, `show METHOD --view il`, `xrefs` |
| Firmware blob | `open`, `list regions`, `extract`, then `open` an extracted file |
| HAR capture | `open`, `list requests --match HOST`, `show REQUEST --view response` |
| Web page (http(s) URL) | `open`, `list scripts`, `list requests`, `show SCRIPT --view source`; `run` only when the question needs a driven session |
| Two versions of anything | `diff A B --what functions` (or any `list` category) |
| EVM bytecode | `open --kind evm`, `list selectors` |

## Reading a reply

Every verb but `doctor` and the ledger forms of `evidence` returns one record:

```json
{"evidence_id": "ev_a483…", "op": "xrefs", "confidence": "observed",
 "engine": "builtin (lief 1.0.0 + capstone 5.0.9)", "unknowns": [], "locations": [], "links": [],
 "result": [{"ref": "0x100000588", "name": "_rea_branch", "type": "call", "at": "0x1000005ac"}]}
```

- `evidence_id` is a content hash of the record. Cite it for every claim. The
  same call on the same file gives the same id, so a repeat adds nothing.
- `result` is the verb's value: a list for `list`, `xrefs` and `trace`; text
  or a dict for `show`; a dict for `open`, `diff`, `extract` and `run`.
- `locations` are the addresses, offsets or paths the result is about; `links`
  are the ids of the Evidence a derived record was computed from.
- An error is `{"error": {"code", "message", "hint"}}` (CLI exit 1, MCP
  `isError`): `bad_input`, `not_found`, `ambiguous` (the hint lists candidates;
  choose one, never the first), `unsupported`, `engine_missing`, `timeout`,
  `too_big`, `failed`. Usable partial analysis is Evidence with `unknowns`.

### Paging

A reply holds at most 64 KiB of result. When the result or `limit` cut it, the
reply carries `"page": {"unit": "items" | "chars", "offset", "next", "total"}`.
Continue with `evidence(id, offset=next)` (CLI: `cleanroom evidence ev_… --offset N`)
until `next` is `null`. Lists page by item, text by character; `offset` and
`limit` are not part of the id, so every page belongs to the one record. An item
that alone exceeds the budget appears as `{"_too_big": index, "bytes": n}`: narrow
with `match` or `show` it alone. Fetch later pages only when they matter.

### Confidence

- `observed`: an engine or parser reported it directly (bytes, symbols,
  disassembly, a manifest entry).
- `derived`: a deterministic function computed it from other Evidence, as
  `trace` and `diff` do; `links` names the inputs.
- `inferred`: a heuristic produced it (an IPC channel pairing, a bundler guess,
  a role read from a name). Report it as a hypothesis.

### Unknowns

Incompleteness is never a fourth confidence value. `unknowns` lists what the
engine did not see and why: a regex budget that expired, a slice not opened, a
stub with no import, a truncated inventory. Carry each one that touches the
question into the answer. An incomplete inventory cannot support "absent":
`diff` says `unknown`, not `removed`, and so should you.

## Engines

A native target takes the `engine` argument, else `CLEANROOM_ENGINE`, else the
first installed of `ghidra`, `hopper`, `builtin`. Every reply names its engine.

| Engine | When | Gives |
|---|---|---|
| Ghidra | Free. The default once installed: `GHIDRA_INSTALL_DIR`, JDK 21 and the `[ghidra]` extra | pseudocode, asm, xrefs, annotations |
| Hopper | Optional, macOS; chosen when installed and Ghidra is not | pseudocode, asm, xrefs, annotations |
| IDA Pro | Only when named with `engine=ida` or `CLEANROOM_ENGINE=ida`; never chosen automatically | pseudocode when the local decompiler is licensed |
| builtin | Always present: lief + capstone | functions, symbols, strings, sections, imports, exports, asm, bytes, xrefs; no pseudocode |

Once bound, CleanRoom never fails over to another engine. No engine is a cloud service.

## What works today (P0)

- Kind: `native` only, through the builtin engine: ELF, Mach-O (thin or FAT;
  the host architecture's slice by default, `arch` for another) and PE.
- Verbs: `open`, `close`, `list`, `show`, `xrefs`, `trace`, `diff`,
  `evidence`, `doctor`. `list` takes `functions`, `symbols`, `strings`,
  `sections`, `imports`, `exports`; `show` takes `auto`, `info`, `asm`, `bytes`.
- A ref is a symbol name (`_rea_leaf`, `puts`), an address (`0x100000550`,
  `ram:0x100000550`) or an address inside a function. Names win over bare hex,
  so `add` is a name; a fragment matching several functions fails `ambiguous`.

`unsupported` today: `show --view pseudo` on builtin (install Ghidra, free);
`engine=ghidra` or `hopper` even when installed (their drivers come later);
`extract`, `run`, `annotate`; and every other kind, so a JS tree, an APK, a URL
or a HAR file fails at `open`. `engine_missing`: not installed; `doctor` says how.

## Plan a request that spans several features or subsystems

1. Turn the request into a checklist of questions and the evidence each answer
   needs. Resolve the target from the conversation and workspace before asking.
2. Check what is already recorded: `evidence` lists the ledger. Reuse a matching
   record; do not open a duplicate target or repeat an identical call.
3. Start with the smallest useful inventory. Follow each question from its entry
   point (`list --match`, then `show`, `xrefs`, `trace`) to its result. Batch
   calls around one hypothesis; expand only when the Evidence leaves a gap.
4. Read packaged resources and configuration (plists, manifests, package files)
   alongside code. Do not infer behaviour from names, strings or layout alone.
5. Corroborate a conclusion with the evidence type it needs. Use `run` only when
   static Evidence cannot answer and the host allows it; name what it ran.
6. Split independent questions. Give each parallel worker a distinct scope and
   the ids of existing Evidence; ask for sources, conclusions and open gaps.
7. Keep a finding ledger: each conclusion with its Evidence ids, confidence,
   search boundary and remaining unknowns, so a later pass can reuse it.

## Report

Keep three things apart in every answer:

- **Observed**: what an engine or parser reported. Cite the `evidence_id`.
- **Derived**: what `trace` or `diff` computed, with the ids in `links`.
- **Inferred**: your reading of the Evidence. Say so, and say what would confirm it.

Never imply that static analysis observed execution. Disassembly, pseudocode and
xrefs describe what the code can do, not what it did: a name is not a role, a
string is not a message sent, a call edge is not a call that ran. Only `run`
observes execution, for the one scenario it captured. Pseudocode is not source.

Before finishing, revisit the checklist:

- [ ] Every question is marked answered, partial or unresolved, with an `evidence_id`.
- [ ] Every `inferred` claim is labelled and has a path to confirmation.
- [ ] Every relevant `unknowns` entry is in the answer; bounded searches are reported as bounded.
- [ ] Absence claims rest on a complete inventory; otherwise they are unknown.
- [ ] The engine and the target identity (`path`, `sha256`, `arch`) are stated.
- [ ] Nothing was executed except through `run`, and each run names its target.
