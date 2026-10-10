# CleanRoom: rules for agents

Read `docs/design.md` first. The sections below are the working rules; the
design doc is the specification. The assistant is Sage.is AI.

## Locked decisions

- PyPI `cleanroom-re`; command, import and Homebrew formula `cleanroom`.
  Python `>=3.12`; CI runs 3.12 and 3.13; the Homebrew launcher runs 3.13.
- `mcp>=2.3,<3` through the low-level `mcp.server.Server`; the registry
  emits the JSON schemas. The CLI is stdlib `argparse` from the same
  registry. Agent guidance is `cleanroom/skill/SKILL.md` only; no MCP prompts.
- Extras only for the heavy engines: `[web]`, `[android]`, `[ghidra]`,
  `[all]`. hatchling, flat layout, static version bumped at release.
- The CLI ledger appends to `~/.cache/cleanroom/ledger.jsonl`, so
  `cleanroom evidence ID --offset N` works across calls.

## Shape

- 12 verbs: `open close list show xrefs trace extract diff run annotate
  evidence doctor`. One `@tool` registry in `tools.py` makes the MCP tool,
  the CLI subcommand and the catalog entry from type hints and docstrings.
- One module per target kind in `cleanroom/kinds/`. A kind exports
  `detect`, `open`, `list`, `show`, `xrefs`, `close`; a missing function
  means the verb is unsupported. `trace` and `diff` live in `graph.py`.
- One Evidence type, one `Fail` type, one JSON-lines worker protocol.
- The line budget in design section 8 is enforced by `tests/test_budget.py`.
  Adapted rea files are listed there and not counted.

## Engines

Local only. Automatic order is `ENGINE_ORDER = ("ghidra", "hopper",
"builtin")`, one constant in `kinds/native.py`. IDA runs only through
`engine="ida"` or `CLEANROOM_ENGINE=ida`. Never a cloud decompiler.

## Attribution

Every file adapted from rea starts with
`Adapted from rea <path>@46c9cba (MIT, (c) morluto); see NOTICE`, then
rea's MIT notice. `NOTICE` lists each one; `tests/test_notice.py` keeps the
two in sync. Verbatim fixtures carry no header.

## Git and make

- Branches `develop` and `master` (never `main`), git-flow-next, tags
  `vX.Y.Z`. The committed `.gitflow` (from `git flow init --shared`) gives
  every clone the `v` tag prefix. Commits, tags and pushes are [MANUALLY]
  unless authorised.
- Targets: `make install`, `make test`, `make lint`, `make fmt`, `make ci`,
  `make build`, `make mcp`, `make doctor`, `make release`.
- `make release` runs `bump_release_version` before `release_finish`, so
  `pyproject.toml` always matches the tag.

## Writing code

- Use `uv` only: `uv run`, `uv sync`, `uvx`. A stray `mcp` 1.x sits in the
  `~/.local` user site and shadows the pinned `mcp>=2.3,<3`.
- Python modules are load-bearing and never delegated. A hook denies any
  single write of 4000 or more characters to `.py`, `.md`, `.txt` and
  `.rst` files; write modules in function-sized edits. Files under `tests/`
  are exempt.
- Tests live in `tests/`; none beside source files.
- Label steps [WE] (run in the CLI session) or [MANUALLY] (a person does
  it). Never [USER] or [ME].
- Run `stat -f "%l %N"` on the Makefile and `.env*` before editing them.
  Edit, Write and `sed -i` break hardlinks.
