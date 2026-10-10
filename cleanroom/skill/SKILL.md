---
name: cleanroom
description: Reverse-engineer a binary, app, site or capture with CleanRoom's verbs and page through its Evidence. Placeholder until P0.9 writes the real skill.
---

# CleanRoom (placeholder)

P0.9 writes the real skill here, rewritten from rea's
`.agents/skills/reverse-engineer-anything` (lines 140-206 and its references).
It will cover:

- Routing: which verb answers which question (`open`, `list`, `show`, `xrefs`,
  `trace`, `diff`, `extract`, `run`, `annotate`, `evidence`, `doctor`, `close`).
- Evidence: every reply carries an `ev_` id, a confidence and its unknowns.
- Paging: a reply holds at most 64 KiB; continue with `evidence ID --offset N`.
- Observations versus inferences, and how to report what was not seen.

Until then run `cleanroom --help` and read `docs/design.md`. This file ships
inside the wheel; `cleanroom setup` copies it to the agent's skill folder.
