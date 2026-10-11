"""Command line: one subcommand per registered verb, plus mcp, catalog, setup and version.

Verbs print JSON. A Fail prints ``{"error": ...}`` and exits 1, a usage error exits 2 and
Ctrl-C exits 130. ``cleanroom mcp`` serves the same registry over stdio; the mcp package
points fd 1 at stderr while it serves, so nothing but the protocol reaches stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from typing import Literal, get_args, get_origin

import cleanroom.graph  # noqa: F401 - registers trace and diff beside the tools.py verbs
from cleanroom import __version__
from cleanroom.evidence import Ledger
from cleanroom.target import Fail, cache_dir
from cleanroom.tools import REGISTRY, SKILL_PATH, Param, Session, invoke, schema, unwrap

PACKAGE = "cleanroom-re"
MCP_ARGV = ["uvx", "--from", PACKAGE, "cleanroom", "mcp"]
INSTRUCTIONS = (
    "CleanRoom reverse-engineers binaries, apps, sites and captures locally. Call open "
    "first, then list, show and xrefs. Every reply carries an evidence_id; a reply over "
    "64 KiB has a page key, and evidence(id, offset) returns the rest. "
    f"Guidance: {SKILL_PATH}"
)
# Verbs the skill documents that a later phase delivers: calling one fails unsupported.
PLANNED = {"extract": "P2", "run": "P2", "annotate": "P1"}


def _json_arg(text: str) -> dict:
    """A dict parameter on the command line: JSON text, or @file.json."""
    if text.startswith("@"):
        with open(text[1:], encoding="utf-8") as f:
            return json.load(f)
    return json.loads(text)


def _add_param(sub: argparse.ArgumentParser, p: Param, first: bool) -> None:
    """Required str and Literal params are positional, as is an optional first one; the
    rest are --flags: bool as --x/--no-x, int typed, list[str] as nargs, dict as JSON."""
    base, _ = unwrap(p.hint)
    origin = get_origin(base) or base
    kw: dict = {"help": p.help or None}
    if origin is Literal:
        kw["choices"] = get_args(base)
    if (p.required or first) and (base is str or origin is Literal):
        sub.add_argument(p.name, **kw if p.required else {**kw, "nargs": "?"})
        return
    kw.update(dest=p.name, default=p.default, required=p.required)
    if base is bool:
        kw["action"] = argparse.BooleanOptionalAction
    elif base is int:
        kw["type"] = int
    elif origin is list:
        kw["nargs"] = "+"
    elif base is dict:
        kw["type"] = _json_arg
    sub.add_argument("--" + p.name.replace("_", "-"), **kw)


def build_parser() -> argparse.ArgumentParser:
    """The CLI: global target options, one subcommand per verb, then the four commands."""
    parser = argparse.ArgumentParser(prog="cleanroom", description=INSTRUCTIONS.split(". ")[0])
    parser.add_argument("-t", "--target", help="path or URL a verb opens before it runs")
    parser.add_argument("--kind", help="override target detection (see open)")
    parser.add_argument("--engine", help="native engine (see open)")
    parser.add_argument("--arch", help="FAT slice (see open)")
    parser.add_argument("--ledger", help="JSONL ledger; default $CLEANROOM_LEDGER or the cache")
    parser.add_argument("--pretty", action="store_true", help="indent the JSON output")
    subs = parser.add_subparsers(dest="command", metavar="verb", required=True)
    defaults = argparse.ArgumentDefaultsHelpFormatter
    for spec in REGISTRY.values():
        sub = subs.add_parser(
            spec.name, help=spec.doc, description=spec.doc, formatter_class=defaults
        )
        for i, p in enumerate(spec.params.values()):
            _add_param(sub, p, i == 0)
    subs.add_parser("mcp", help="serve the verbs over stdio to an MCP client")
    subs.add_parser("catalog", help="print every verb with its JSON schema")
    setup = subs.add_parser("setup", help="print MCP registration lines for agents")
    setup.add_argument("--write", action="store_true", help="edit Claude Code config (later)")
    subs.add_parser("version", help="print the version")
    return parser


def _ledger_path(ns: argparse.Namespace) -> str:
    return ns.ledger or os.environ.get("CLEANROOM_LEDGER") or str(cache_dir() / "ledger.jsonl")


def _open_args(ns: argparse.Namespace) -> dict:
    return {"path": ns.target, "kind": ns.kind, "engine": ns.engine, "arch": ns.arch}


def run_verb(ns: argparse.Namespace) -> dict:
    """Open -t when the verb needs a target, run the verb, close; the ledger persists."""
    spec = REGISTRY[ns.command]
    session = Session(Ledger(_ledger_path(ns)))
    try:
        if spec.needs_target:
            if not ns.target:
                raise Fail("not_found", "no target open", "pass -t/--target PATH before the verb")
            invoke(session, REGISTRY["open"], _open_args(ns))
        return invoke(session, spec, {n: getattr(ns, n) for n in spec.params})
    finally:
        session.close()


def catalog() -> dict:
    tools = [
        {"name": s.name, "description": s.doc, "input_schema": schema(s), "read_only": s.read_only}
        for s in REGISTRY.values()
    ]
    return {"tools": tools}


def setup_lines() -> dict:
    """Registration for each agent. Until the package is on PyPI, use the checkout form."""
    snippet = {"mcpServers": {"cleanroom": {"command": MCP_ARGV[0], "args": MCP_ARGV[1:]}}}
    return {
        "claude": "claude mcp add cleanroom -- " + " ".join(MCP_ARGV),
        "codex": "codex mcp add cleanroom -- " + " ".join(MCP_ARGV),
        "cursor": {"file": "~/.cursor/mcp.json", **snippet},
        "generic": snippet,
        "checkout": "uv run --directory <CleanRoom checkout> cleanroom mcp",
        "skill": {"from": str(SKILL_PATH), "to": "~/.claude/skills/cleanroom/SKILL.md"},
    }


def serve_mcp(ns: argparse.Namespace) -> int:
    """Serve the registry over stdio with the low-level mcp Server (imported here, lazily)."""
    import anyio
    from mcp import types
    from mcp.server import Server
    from mcp.server.stdio import stdio_server

    session = Session(Ledger(_ledger_path(ns)))

    def error(f: Fail) -> types.CallToolResult:
        text = json.dumps({"error": f.to_dict()}, ensure_ascii=False)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=text)], is_error=True
        )

    async def list_tools(ctx, params) -> types.ListToolsResult:
        tools = [
            types.Tool(
                name=s.name,
                description=s.doc,
                input_schema=schema(s),
                annotations=types.ToolAnnotations(read_only_hint=s.read_only),
            )
            for s in REGISTRY.values()
        ]
        return types.ListToolsResult(tools=tools)

    async def call_tool(ctx, params) -> types.CallToolResult:
        spec, args = REGISTRY.get(params.name), dict(params.arguments or {})
        try:
            if spec is None and params.name in PLANNED:
                when, today = PLANNED[params.name], "today: " + ", ".join(REGISTRY)
                raise Fail("unsupported", f"{params.name} arrives in {when}", today)
            if spec is None:
                raise Fail("not_found", f"no tool {params.name!r}", ", ".join(REGISTRY))
            fn = lambda: invoke(session, spec, args)  # noqa: E731 - bound here, run off-loop
            reply = await anyio.to_thread.run_sync(fn, abandon_on_cancel=True)
        except Fail as f:
            return error(f)
        except Exception as e:  # noqa: BLE001 - every other failure is reported as failed
            traceback.print_exc()
            return error(Fail("failed", f"{type(e).__name__}: {e}"))
        text = json.dumps(reply, ensure_ascii=False)
        content = [types.TextContent(type="text", text=text)]
        return types.CallToolResult(content=content, structured_content=reply)

    server = Server(
        "cleanroom",
        version=__version__,
        instructions=INSTRUCTIONS,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )

    async def run() -> None:
        if ns.target:
            invoke(session, REGISTRY["open"], _open_args(ns))
        async with stdio_server() as (r, w):
            await server.run(r, w, server.create_initialization_options())

    try:
        anyio.run(run)
    finally:
        session.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run one command. Output is JSON on stdout; in mcp mode an error goes to stderr instead,
    because nothing but the protocol may reach stdout there. Any other exception is ``failed``."""
    ns = build_parser().parse_args(argv)
    out_err = sys.stderr if ns.command == "mcp" else sys.stdout
    try:
        if ns.command == "version":
            print(f"cleanroom {__version__}")
        elif ns.command == "mcp":
            return serve_mcp(ns)
        elif ns.command == "setup" and ns.write:
            print("cleanroom setup --write: not implemented yet", file=sys.stderr)
            return 2
        else:
            commands = {"catalog": catalog, "setup": setup_lines}
            out = commands[ns.command]() if ns.command in commands else run_verb(ns)
            layout = {"indent": 1} if ns.pretty else {"separators": (",", ":")}
            print(json.dumps(out, ensure_ascii=False, **layout))
    except Fail as f:
        print(json.dumps({"error": f.to_dict()}, ensure_ascii=False), file=out_err)
        return 1
    except KeyboardInterrupt:
        return 130
    except Exception as e:  # noqa: BLE001 - the traceback goes to stderr, the JSON stays
        traceback.print_exc()
        f = Fail("failed", f"{type(e).__name__}: {e}")
        print(json.dumps({"error": f.to_dict()}, ensure_ascii=False), file=out_err)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
