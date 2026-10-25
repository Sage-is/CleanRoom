"""A synthetic n8n-nodes-base package for the n8n kind tests. No n8n data.

``build(root)`` writes ``package.json`` and ``dist/types/{nodes,credentials}.json``. Node
``acme`` has two descriptions: version 1 with no requests, and versions 2 and 2.1, which are
declarative. Its widget resource has ``get`` (the URL names ``widgetId``) and ``create``
(one function hook, which JSON keeps as null). ``acmeApi`` is a generic key credential and
``acmeOAuth2Api`` extends OAuth2.
"""

from __future__ import annotations

import json
from pathlib import Path

OLD = {"displayName": "Acme", "name": "acme", "version": 1, "properties": []}
GET = {"method": "GET", "url": "=/w/{{$parameter.widgetId}}"}
CREATE = {"request": {"method": "POST", "url": "/w"}, "send": {"preSend": [None]}}
NEW = {
    "displayName": "Acme",
    "name": "acme",
    "version": [2, 2.1],
    "credentials": [{"name": "acmeApi", "required": True}],
    "requestDefaults": {"baseURL": "https://api.acme.test/v1"},
    "properties": [
        {"name": "resource", "type": "options", "options": [{"value": "widget"}]},
        {
            "name": "operation",
            "type": "options",
            "displayOptions": {"show": {"resource": ["widget"]}},
            "options": [
                {"value": "get", "routing": {"request": GET}},
                {"value": "create", "routing": CREATE},
            ],
        },
        {"name": "widgetId", "type": "string", "required": True},
    ],
}
CREDENTIALS = [
    {
        "name": "acmeApi",
        "properties": [{"name": "apiKey", "type": "string"}],
        "authenticate": {"type": "generic", "properties": {"headers": {"X-Key": "k"}}},
        "test": {"request": {"url": "/me"}},
    },
    {"name": "acmeOAuth2Api", "extends": ["oAuth2Api"], "properties": []},
]


def build(root: Path, nodes: list[dict] | None = None, version: str = "9.9.9") -> Path:
    types = root / "dist" / "types"
    types.mkdir(parents=True)
    (root / "package.json").write_text(json.dumps({"name": "n8n-nodes-base", "version": version}))
    (types / "nodes.json").write_text(json.dumps([OLD, NEW] if nodes is None else nodes))
    (types / "credentials.json").write_text(json.dumps(CREDENTIALS))
    return root
