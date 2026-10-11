"""__main__.py as a subprocess: help, version, catalog, setup, and verbs over the fake kind.

The fake kind reaches the child through ``tests/fixtures/fake_main.py``, a wrapper
that registers it and then calls the real ``main``; the entry point has no test hook.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import cleanroom.graph  # noqa: F401 - __main__ registers trace and diff; match it in-process
from cleanroom import __version__
from cleanroom.tools import REGISTRY

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
COMMANDS = ("mcp", "catalog", "setup", "version")


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


FAKE_MAIN = str(FIXTURES / "fake_main.py")


def cli(*args: str, env: dict[str, str], plain: bool = False) -> subprocess.CompletedProcess[str]:
    """Run the CLI with the fake kind registered, or ``plain`` for the bare entry point."""
    argv = [sys.executable, *(["-m", "cleanroom"] if plain else [FAKE_MAIN]), *args]
    return subprocess.run(argv, capture_output=True, text=True, env=env, cwd=ROOT, timeout=60)


def ok(*args: str, env: dict[str, str]) -> dict:
    done = cli(*args, env=env)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def error(*args: str, env: dict[str, str]) -> dict:
    done = cli(*args, env=env)
    assert done.returncode == 1, (done.stdout, done.stderr)
    body = json.loads(done.stdout)
    assert set(body) == {"error"} and set(body["error"]) >= {"code", "message"}
    return body["error"]


def test_uv_run_help_lists_every_verb(env: dict[str, str]) -> None:
    if shutil.which("uv") is None:
        pytest.skip("uv not on PATH")
    done = subprocess.run(
        ["uv", "run", "cleanroom", "--help"], capture_output=True, text=True, cwd=ROOT, timeout=120
    )
    assert done.returncode == 0, done.stderr
    for name in (*REGISTRY, *COMMANDS):
        assert f"\n    {name} " in done.stdout, name
    assert "-t TARGET" in done.stdout and "--ledger" in done.stdout


def test_verb_help_shows_flags_and_choices(env: dict[str, str]) -> None:
    done = cli("list", "--help", env=env)
    assert done.returncode == 0
    assert "what" in done.stdout and "--match" in done.stdout and "--limit" in done.stdout
    assert "(default: 200)" in done.stdout
    done = cli("xrefs", "--help", env=env)
    assert "{to,from,both}" in done.stdout
    done = cli("evidence", "--help", env=env)
    assert "[id]" in done.stdout and "--import" in done.stdout and "--export" in done.stdout


def test_version(env: dict[str, str]) -> None:
    done = cli("version", env=env)
    assert done.returncode == 0 and done.stdout == f"cleanroom {__version__}\n"


def test_catalog_lists_each_verb_once(env: dict[str, str]) -> None:
    body = ok("catalog", env=env)
    names = [t["name"] for t in body["tools"]]
    assert len(names) == len(set(names)) >= 7
    assert set(REGISTRY) == set(names)
    for t in body["tools"]:
        assert set(t) == {"name", "description", "input_schema", "read_only"}
        assert t["input_schema"]["type"] == "object"
    by_name = {t["name"]: t for t in body["tools"]}
    assert by_name["list"]["input_schema"]["required"] == ["what"]
    assert by_name["doctor"]["read_only"] is True


def test_setup_prints_registration_lines(env: dict[str, str]) -> None:
    body = ok("setup", env=env)
    assert body["claude"] == "claude mcp add cleanroom -- uvx --from cleanroom-re cleanroom mcp"
    assert body["codex"].startswith("codex mcp add cleanroom -- ")
    assert body["cursor"]["mcpServers"]["cleanroom"]["command"] == "uvx"
    assert body["generic"]["mcpServers"]["cleanroom"]["args"][-1] == "mcp"
    assert body["skill"]["from"].endswith("SKILL.md")
    done = cli("setup", "--write", env=env)
    assert done.returncode == 2 and "not implemented" in done.stderr and done.stdout == ""


def test_usage_errors_exit_2(env: dict[str, str]) -> None:
    assert cli(env=env).returncode == 2
    assert cli("list", env=env).returncode == 2
    assert cli("xrefs", "a", "--direction", "sideways", env=env).returncode == 2
    assert cli("list", "things", "--limit", "many", env=env).returncode == 2
    assert cli("nosuch", env=env).returncode == 2


def test_open_then_list_through_the_target_option(env: dict[str, str], fake_file: Path) -> None:
    body = ok("-t", str(fake_file), "list", "things", env=env)
    assert body["op"] == "list" and body["engine"] == "fake 1.0"
    assert [x["name"] for x in body["result"]] == ["alpha", "beta", "gamma"]
    assert "page" not in body
    assert body["evidence_id"].startswith("ev_")
    lines = Path(env["CLEANROOM_LEDGER"]).read_text().splitlines()
    assert [json.loads(ln)["op"] for ln in lines] == ["open", "list"]
    again = ok("-t", str(fake_file), "list", "things", "--match", "beta", env=env)
    assert [x["name"] for x in again["result"]] == ["beta"]


def test_open_verb_reports_identity_and_vocabulary(env: dict[str, str], fake_file: Path) -> None:
    body = ok("open", str(fake_file), "--engine", "fake 9", env=env)
    result = body["result"]
    assert result["kind"] == "fake" and result["engine"] == "fake 9"
    assert result["list"] == ["things"] and result["views"] == ["auto", "info"]
    assert result["size"] == 8 and len(result["sha256"]) == 64


def test_evidence_id_offset_repages_across_calls(env: dict[str, str], fake_file: Path) -> None:
    first = ok("-t", str(fake_file), "list", "things", "--limit", "1", env=env)
    assert first["page"] == {"unit": "items", "offset": 0, "next": 1, "total": 3}
    eid = first["evidence_id"]
    second = ok("evidence", eid, "--offset", "1", "--limit", "1", env=env)
    assert second["evidence_id"] == eid
    assert [x["name"] for x in second["result"]] == ["beta"]
    assert second["page"] == {"unit": "items", "offset": 1, "next": 2, "total": 3}
    rest = ok("evidence", eid, "--offset", "2", env=env)
    assert [x["name"] for x in rest["result"]] == ["gamma"]
    assert rest["page"]["next"] is None
    index = ok("evidence", env=env)
    assert index["count"] == 2 and {r["op"] for r in index["records"]} == {"open", "list"}
    assert error("evidence", "ev_nope", env=env)["code"] == "not_found"


def test_evidence_export_and_import(env: dict[str, str], fake_file: Path, tmp_path: Path) -> None:
    ok("-t", str(fake_file), "xrefs", "beta", env=env)
    out = tmp_path / "export.jsonl"
    assert ok("evidence", "--export", str(out), env=env)["exported"] == 2
    other = {**env, "CLEANROOM_LEDGER": str(tmp_path / "other.jsonl")}
    assert ok("evidence", "--import", str(out), env=other)["imported"] == 2
    assert ok("evidence", env=other)["count"] == 2


def test_bad_ref_exits_1_with_a_code(env: dict[str, str], fake_file: Path) -> None:
    err = error("-t", str(fake_file), "show", "nope", env=env)
    assert err["code"] == "not_found" and "nope" in err["message"]
    err = error("-t", str(fake_file), "show", "alpha", "--view", "pseudo", env=env)
    assert err["code"] == "bad_input"
    err = error("-t", str(fake_file), "list", "functions", env=env)
    assert err["code"] == "bad_input"


def test_missing_target_exits_1_not_found(env: dict[str, str], tmp_path: Path) -> None:
    assert error("list", "things", env=env)["code"] == "not_found"
    assert error("-t", str(tmp_path / "gone"), "list", "things", env=env)["code"] == "not_found"


def test_finding_confidence_survives_the_cli(env: dict[str, str], fake_file: Path) -> None:
    body = ok("-t", str(fake_file), "xrefs", "0x20", "--direction", "to", env=env)
    assert body["confidence"] == "inferred" and body["unknowns"]
    assert body["result"] == [{"ref": "0x10", "name": "alpha", "type": "call", "at": "0x14"}]


def test_doctor_runs_without_a_target(env: dict[str, str], tmp_path: Path) -> None:
    body = ok("doctor", env=env)
    assert body["engines"]["builtin"].startswith("lief ")
    assert body["libraries"]["mcp"] and body["version"] == __version__
    assert body["ledger"] == env["CLEANROOM_LEDGER"]
    assert body["cache"] == str(tmp_path / "cache")
    assert not Path(env["CLEANROOM_LEDGER"]).exists()


def test_the_bare_entry_point_knows_no_fake_kind(env: dict[str, str], fake_file: Path) -> None:
    done = cli("-t", str(fake_file), "list", "things", env=env, plain=True)
    assert done.returncode == 1
    err = json.loads(done.stdout)["error"]
    assert err["code"] == "unsupported" and "native" in err["hint"]


def test_url_open_is_unsupported_until_web_lands(env: dict[str, str]) -> None:
    err = error("open", "https://example.test/app", env=env)
    assert err["code"] == "unsupported" and "web" in err["message"]
    assert "installed" in err["hint"]
    err = error("-t", "https://example.test/app", "list", "things", env=env)
    assert err["code"] == "unsupported"


def test_unwritable_ledger_is_a_json_failure(env: dict[str, str], fake_file: Path) -> None:
    bad = {**env, "CLEANROOM_LEDGER": str(fake_file / "under-a-file" / "ledger.jsonl")}
    done = cli("-t", str(fake_file), "list", "things", env=bad)
    assert done.returncode == 1
    err = json.loads(done.stdout)["error"]
    assert err["code"] == "failed" and "cannot write ledger" in err["message"]
    assert "CLEANROOM_LEDGER" in err["hint"]


def test_any_other_exception_is_failed_json(env: dict[str, str], fake_file: Path) -> None:
    code = (
        f"import sys; sys.path.insert(0, {str(ROOT)!r}); from tests.fixtures import fake_main; "
        "from cleanroom.kinds import fake; fake.list = lambda *a, **k: 1 / 0; "
        "from cleanroom.__main__ import main; sys.exit(main())"
    )
    argv = [sys.executable, "-c", code, "-t", str(fake_file), "list", "things"]
    done = subprocess.run(argv, capture_output=True, text=True, env=env, cwd=ROOT, timeout=60)
    assert done.returncode == 1
    assert json.loads(done.stdout) == {
        "error": {"code": "failed", "message": "ZeroDivisionError: division by zero"}
    }
    assert "Traceback" in done.stderr


def test_pretty_flag_indents_and_default_is_compact(env: dict[str, str]) -> None:
    compact = cli("catalog", env=env)
    assert compact.returncode == 0 and compact.stdout.count("\n") == 1
    pretty = cli("--pretty", "catalog", env=env)
    assert pretty.returncode == 0 and pretty.stdout.count("\n") > 10
    assert json.loads(pretty.stdout) == json.loads(compact.stdout)


def test_mcp_with_a_missing_target_keeps_stdout_clean(env: dict[str, str], tmp_path: Path) -> None:
    done = cli("-t", str(tmp_path / "gone"), "mcp", env=env)
    assert done.returncode == 1 and done.stdout == ""
    assert json.loads(done.stderr.strip().splitlines()[-1])["error"]["code"] == "not_found"
