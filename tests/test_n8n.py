"""n8n kind: detection, the inventories, show views, xrefs and the verbs.

Every test but the last runs on the synthetic package in ``tests/fixtures/n8n.py``. The last
reads a real ``n8n-nodes-base`` when ``CLEANROOM_N8N_PACKAGE`` names its directory; n8n data
is never committed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import cleanroom.graph  # noqa: F401 - registers trace and diff
from cleanroom.evidence import Ledger
from cleanroom.kinds import n8n
from cleanroom.target import Fail, detect, open_target
from cleanroom.tools import REGISTRY, Session, invoke
from tests.fixtures import n8n as fx

PACKAGE = os.environ.get("CLEANROOM_N8N_PACKAGE")


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLEANROOM_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("CLEANROOM_LEDGER", str(tmp_path / "ledger.jsonl"))


@pytest.fixture(scope="module")
def package(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return fx.build(tmp_path_factory.mktemp("n8n") / "pkg")


@pytest.fixture(scope="module")
def handle(package: Path) -> n8n.Handle:
    return n8n.open(open_target(str(package)))


def rows(h: n8n.Handle, what: str) -> dict[str, dict]:
    return {r["ref"]: r for r in n8n.list(h, what)}


def test_detect_package_types_dir_and_file(package: Path, tmp_path: Path) -> None:
    types = package / "dist" / "types"
    for path in (package, types, types / "nodes.json"):
        assert detect(str(path), b"") == "n8n"
    other = tmp_path / "other"
    other.mkdir()
    (other / "nodes.json").write_text(json.dumps({"log": {"entries": []}}))
    (other / "credentials.json").write_text("[]")
    assert not n8n.detect(str(other), b"")
    assert not n8n.detect(str(tmp_path / "missing"), b"")


def test_open_and_info(handle: n8n.Handle) -> None:
    info = n8n.info(handle)
    assert info["format"] == "n8n-nodes-base 9.9.9" and info["engine"] == "builtin-n8n"
    assert (info["nodes"], info["descriptions"], info["declarative"]) == (1, 2, 1)
    assert info["credentials"] == 2 and len(info["content_sha256"]) == 64


def test_nodes_list_style_hooks_and_credentials(handle: n8n.Handle) -> None:
    nodes = rows(handle, "nodes")
    assert set(nodes) == {"acme@1", "acme@2,2.1"}
    new = nodes["acme@2,2.1"]
    assert new["style"] == "declarative" and nodes["acme@1"]["style"] == "programmatic"
    assert new["hooks"] == 1 and new["credentials"] == ["acmeApi"]
    assert new["base_url"] == "https://api.acme.test/v1" and "_raw" not in new


def test_operations_come_from_the_newest_description(handle: n8n.Handle) -> None:
    ops = rows(handle, "operations")
    assert set(ops) == {"acme/widget/get", "acme/widget/create"}
    get, create = ops["acme/widget/get"], ops["acme/widget/create"]
    assert (get["method"], get["parameters"], get["hooks"]) == ("GET", ["widgetId"], 0)
    assert (create["method"], create["hooks"], create["node"]) == ("POST", 1, "acme@2,2.1")


def test_credentials_auth(handle: n8n.Handle) -> None:
    creds = rows(handle, "credentials")
    key, oauth = creds["credential:acmeApi"], creds["credential:acmeOAuth2Api"]
    assert (key["auth"], key["fields"], key["test"]) == ("generic", ["apiKey"], True)
    assert (oauth["auth"], oauth["test"]) == ("oauth2", False)


def test_list_match_filters_by_name(handle: n8n.Handle) -> None:
    assert [r["ref"] for r in n8n.list(handle, "operations", "create")] == ["acme/widget/create"]


def test_show_views(handle: n8n.Handle) -> None:
    auto = n8n.show(handle, "acme")
    assert auto["ref"] == "acme@2,2.1"
    assert auto["links"] == ["credential:acmeApi", "acme/widget/get", "acme/widget/create"]
    assert "links" not in n8n.show(handle, "acme@1", "info")
    assert n8n.show(handle, "acme/widget/get", "routing")["routing"]["request"]["method"] == "GET"
    assert n8n.show(handle, "credential:acmeApi", "routing")["test"] == {"request": {"url": "/me"}}
    assert n8n.show(handle, "acme@1", "json")["version"] == 1


def test_xrefs(handle: n8n.Handle) -> None:
    into = n8n.xrefs(handle, "credential:acmeApi", "to")
    assert into == [{"ref": "acme@2,2.1", "type": "credential"}]
    both = n8n.xrefs(handle, "acme/widget/get")
    assert both == [{"ref": "acme@2,2.1", "type": "operation", "direction": "to"}]


def test_failures(handle: n8n.Handle, package: Path) -> None:
    for call, code in (
        (lambda: n8n.list(handle, "widgets"), "bad_input"),
        (lambda: n8n.show(handle, "acme", "asm"), "bad_input"),
        (lambda: n8n.show(handle, "nope"), "not_found"),
        (lambda: n8n.xrefs(handle, "acme", "sideways"), "bad_input"),
        (lambda: n8n.open(open_target(str(package)), engine="ghidra"), "unsupported"),
    ):
        with pytest.raises(Fail) as err:
            call()
        assert err.value.code == code


def run(session: Session, verb: str, **args) -> dict:
    return invoke(session, REGISTRY[verb], args)


def test_verbs_open_list_and_diff(package: Path, tmp_path: Path) -> None:
    session = Session(Ledger(str(tmp_path / "ledger.jsonl")))
    opened = run(session, "open", path=str(package))["result"]
    assert opened["kind"] == "n8n" and "operations" in opened["list"]
    newer = fx.NEW | {"version": 3, "properties": fx.NEW["properties"][:2]}
    other = fx.build(tmp_path / "other", nodes=[fx.OLD, newer], version="10.0.0")
    reply = run(session, "diff", a=str(package), b=str(other), what="nodes")
    assert reply["result"]["categories"]["nodes"]["added"] == ["acme@3"]
    assert reply["result"]["categories"]["nodes"]["removed"] == ["acme@2,2.1"]


# --- a real package, when one is named ------------------------------------------------


@pytest.mark.skipif(not PACKAGE, reason="set CLEANROOM_N8N_PACKAGE to an n8n-nodes-base dir")
def test_real_package() -> None:
    h = n8n.open(open_target(PACKAGE))
    info = n8n.info(h)
    assert info["nodes"] > 100 and info["credentials"] > 100 and info["declarative"] > 0
    assert len(n8n.list(h, "operations")) > info["nodes"]
