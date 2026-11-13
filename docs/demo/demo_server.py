#!/usr/bin/env python3
"""Demo launcher: the real MCP server wired to a *mock* Log Analytics workspace.

Used to record ``docs/demo/sentinel-pipeline.cast`` and the README
screenshots. It never touches Azure:

- Credentials are all-zero placeholder GUIDs and a stub MSAL app that
  returns a dummy token. No certificate is read.
- ``LOGANALYTICS_API_BASE`` points at an in-process HTTP server on
  127.0.0.1 that returns canned, fictional rows (RFC 5737 TEST-NET IPs,
  ``contoso.local`` hosts) for ``/query`` and the bundled snapshot for
  ``/metadata``.

Everything else (tool definitions, validation, conversion, audit log) is
the production code path.

    python docs/demo/demo_server.py      # speaks MCP over stdio
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from mcp.server.stdio import stdio_server

from mcp_sentinel_detection_engine.auth import (
    DEFAULT_TENANT_KEY,
    AzureCredentials,
    CredentialProvider,
    TokenManager,
)
from mcp_sentinel_detection_engine.schemas.loader import load_schema
from mcp_sentinel_detection_engine.server import build_server

PLACEHOLDER = "00000000-0000-0000-0000-000000000000"

_ROWS = [
    ["2026-11-13T08:02:11Z", "DC01.contoso.local", "CONTOSO\\svc-backup", "203.0.113.24", 4625, 3],
    ["2026-11-13T08:02:14Z", "DC01.contoso.local", "CONTOSO\\svc-backup", "203.0.113.24", 4625, 3],
    [
        "2026-11-13T08:02:19Z",
        "DC01.contoso.local",
        "CONTOSO\\administrator",
        "203.0.113.24",
        4625,
        3,
    ],
    [
        "2026-11-13T08:02:23Z",
        "DC01.contoso.local",
        "CONTOSO\\administrator",
        "203.0.113.24",
        4625,
        3,
    ],
    ["2026-11-13T08:41:57Z", "FS02.contoso.local", "CONTOSO\\jdoe", "198.51.100.7", 4625, 3],
]
_COLUMNS = [
    {"name": "TimeGenerated", "type": "datetime"},
    {"name": "Computer", "type": "string"},
    {"name": "Account", "type": "string"},
    {"name": "IpAddress", "type": "string"},
    {"name": "EventID", "type": "int"},
    {"name": "LogonType", "type": "int"},
]


class _MockLogAnalytics(BaseHTTPRequestHandler):
    def _send(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        query = str(json.loads(self.rfile.read(length) or b"{}").get("query", ""))
        take = re.findall(r"\|\s*take\s+(\d+)", query)
        rows = _ROWS[: int(take[-1])] if take else _ROWS
        self._send({"tables": [{"name": "PrimaryResult", "columns": _COLUMNS, "rows": rows}]})

    def do_GET(self) -> None:
        tables = [
            {"name": name, "columns": [{"name": c, "type": t} for c, t in entry["columns"].items()]}
            for name, entry in load_schema()["tables"].items()
        ]
        self._send({"tables": tables})

    def log_message(self, format: str, *args: Any) -> None:
        del format, args


class _DemoProvider(CredentialProvider):
    def get_credentials(self, tenant_key: str = DEFAULT_TENANT_KEY) -> AzureCredentials:
        del tenant_key
        return AzureCredentials(
            tenant_id=PLACEHOLDER,
            client_id=PLACEHOLDER,
            cert_path="/dev/null",
            workspace_id=PLACEHOLDER,
        )


class _StubMsal:
    def acquire_token_for_client(self, scopes: list[str]) -> dict[str, Any]:
        del scopes
        return {"access_token": "demo-token", "expires_in": 3600}


async def _main() -> None:
    mock = ThreadingHTTPServer(("127.0.0.1", 0), _MockLogAnalytics)
    threading.Thread(target=mock.serve_forever, daemon=True).start()
    os.environ["LOGANALYTICS_API_BASE"] = f"http://127.0.0.1:{mock.server_address[1]}"

    token_manager = TokenManager(_DemoProvider(), msal_factory=lambda **_: _StubMsal())
    server = build_server(token_manager)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
