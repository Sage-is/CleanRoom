"""``cleanroom mcp`` as a stdio subprocess: the mcp client API, then rea's golden initialize."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
GOLDEN = FIXTURES / "golden" / "mcp-initialize.json"
SERVER = [sys.executable, str(FIXTURES / "fake_main.py"), "mcp"]  # the fake kind registered


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    return {
        **os.environ,
        "CLEANROOM_CACHE": str(tmp_path / "cache"),
        "CLEANROOM_LEDGER": str(tmp_path / "ledger.jsonl"),
    }


@pytest.fixture
def fake_file(tmp_path: Path) -> Path:
    p = tmp_path / "toy.bin"
    p.write_bytes(b"FAKE\x00toy")
    return p


def with_client(env: dict[str, str], body: Callable[[ClientSession], Awaitable[Any]]) -> Any:
    """Spawn the server, initialize a ClientSession and run ``body`` against it."""
    params = StdioServerParameters(command=SERVER[0], args=SERVER[1:], env=env, cwd=ROOT)

    async def main() -> Any:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                assert init.server_info.name == "cleanroom"
                return await body(session)

    return anyio.run(main)


def error_of(result: Any) -> dict:
    assert result.is_error is True
    body = json.loads(result.content[0].text)
    assert set(body) == {"error"}
    return body["error"]


def test_list_tools_has_every_verb(env: dict[str, str]) -> None:
    async def body(session: ClientSession) -> None:
        listed = await session.list_tools()
        tools = {t.name: t for t in listed.tools}
        assert {"open", "close", "list", "show", "xrefs", "evidence", "doctor"} <= set(tools)
        assert tools["open"].input_schema["required"] == ["path"]
        assert tools["list"].annotations.read_only_hint is True
        assert tools["evidence"].annotations.read_only_hint is False  # export writes a file
        assert tools["xrefs"].input_schema["properties"]["direction"]["enum"] == [
            "to",
            "from",
            "both",
        ]
        assert "evidence" in (session.instructions or "")

    with_client(env, body)


def test_doctor_succeeds_and_list_without_target_fails(env: dict[str, str]) -> None:
    async def body(session: ClientSession) -> None:
        doctor = await session.call_tool("doctor", {})
        assert doctor.is_error is False
        assert doctor.structured_content["engines"]["builtin"].startswith("lief ")
        assert json.loads(doctor.content[0].text)["tools"] == doctor.structured_content["tools"]
        listed = await session.call_tool("list", {"what": "things"})
        assert error_of(listed) == {
            "code": "not_found",
            "message": "no target open",
            "hint": "call open first",
        }

    with_client(env, body)


def test_open_list_and_bad_ref(env: dict[str, str], fake_file: Path) -> None:
    async def body(session: ClientSession) -> None:
        opened = await session.call_tool("open", {"path": str(fake_file)})
        assert opened.is_error is False
        assert opened.structured_content["result"]["kind"] == "fake"
        listed = await session.call_tool("list", {"what": "things", "limit": 2})
        reply = listed.structured_content
        assert [x["name"] for x in reply["result"]] == ["alpha", "beta"]
        assert reply["page"] == {"unit": "items", "offset": 0, "next": 2, "total": 3}
        more = await session.call_tool("evidence", {"id": reply["evidence_id"], "offset": 2})
        assert [x["name"] for x in more.structured_content["result"]] == ["gamma"]
        bad = await session.call_tool("show", {"ref": "nope"})
        assert error_of(bad)["code"] == "not_found"
        assert (
            error_of(await session.call_tool("list", {"what": "things", "limit": True}))["code"]
            == "bad_input"
        )
        assert error_of(await session.call_tool("nosuch", {}))["code"] == "not_found"
        planned = error_of(await session.call_tool("extract", {}))
        assert planned["code"] == "unsupported" and "P2" in planned["message"]
        assert "open" in planned["hint"]
        closed = await session.call_tool("close", {})
        assert closed.structured_content["result"] == {"closed": str(fake_file)}

    with_client(env, body)
    ops = [json.loads(ln)["op"] for ln in Path(env["CLEANROOM_LEDGER"]).read_text().splitlines()]
    assert ops == ["open", "list", "close"]


def test_golden_initialize_over_raw_stdio(env: dict[str, str]) -> None:
    request = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert request["id"] == 0 and request["method"] == "initialize"
    proc = subprocess.Popen(
        SERVER,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=ROOT,
    )
    out, err = proc.communicate(json.dumps(request).encode() + b"\n", timeout=60)
    assert proc.returncode == 0, err.decode()
    lines = out.decode("utf-8").splitlines()
    assert len(lines) == 1, out  # nothing but the protocol reaches stdout
    reply = json.loads(lines[0])
    assert reply["jsonrpc"] == "2.0" and reply["id"] == 0
    assert reply["result"]["serverInfo"]["name"] == "cleanroom"
    assert reply["result"]["capabilities"]["tools"] is not None
    assert "error" not in reply
