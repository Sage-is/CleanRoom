# CleanRoom

CleanRoom is a local-only Python 3.12 reimplementation of
[morluto/rea](https://github.com/morluto/rea) (MIT), the "Reverse Engineer
Anything" MCP server and CLI. It keeps rea's analysis surface (native
binaries, JavaScript and Electron, web pages, HAR files, .NET, Android, Apple
bundles, EVM bytecode and process captures) in 12 verbs, one Evidence type
and one module per target kind, in under 8,000 lines. rea's ideas, edge cases
and some code are adapted with credit; see `NOTICE`.

## Status

Pre-release. P0 (core, CLI, MCP and the builtin native engine) is in
progress. Nothing is published yet.

## Install

Once released:

    uvx --from cleanroom-re cleanroom
    brew tap sage-is/apps && brew install cleanroom

From a checkout: `make install`, then `uv run cleanroom`.

## Verbs

| Verb | Inputs | Meaning |
|---|---|---|
| `open` | `target`, `kind?`, `engine?`, `arch?` | Detect and bind a target |
| `close` | none | Close the target and its workers |
| `list` | `what`, `match?`, `offset=0`, `limit=200` | List functions, strings, files, requests and more |
| `show` | `ref`, `view=auto` | Inspect one item |
| `xrefs` | `ref`, `direction=to\|from\|both` | References into, out of, or both ways |
| `trace` | `start`, `goal?`, `depth=3` | Breadth-first search over xrefs |
| `extract` | `target`, `out_dir` | Unpack ZIP, ASAR, DMG, firmware or JS bundles |
| `diff` | `a`, `b`, `what?` | Keyed diff of `list` output |
| `run` | `argv` or `url`, `steps?`, `breakpoints?`, `timeout=30` | Capture a process or browser run |
| `annotate` | `ref`, `name?`, `comment?` | Native annotations, read back |
| `evidence` | `id?`, `offset?`, `export?`, `import?` | Page, export or import Evidence |
| `doctor` | none | Report engines, libraries and prerequisites |

Every result is Evidence: a record with a stable `ev_` ID, the engine that
produced it, a confidence and its unknowns. Large results page through
`evidence`.

## MCP

    claude mcp add cleanroom -- uvx --from cleanroom-re cleanroom mcp

## Engines

Every engine decompiles on your machine. CleanRoom never sends code to a
cloud decompiler.

| Engine | Role |
|---|---|
| Ghidra | Free default; needs JDK 21 |
| Hopper | Optional |
| IDA Pro 9+ | Only when named: `engine=ida` or `CLEANROOM_ENGINE=ida` |
| builtin (lief + capstone) | Always available; functions, strings, asm, xrefs; no pseudocode |

## Development

    make install   # uv sync --locked --all-extras
    make test      # pytest -m "not live"
    make ci        # lint, tests, build

Design: [docs/design.md](docs/design.md). Survey of rea:
[docs/research/](docs/research/).

## License

AGPL-3.0-or-later. Adapted rea files keep their MIT notice; `NOTICE` lists
them.
