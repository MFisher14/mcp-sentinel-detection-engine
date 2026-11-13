"""Live workspace schema fetched from the Log Analytics metadata API.

``GET /v1/workspaces/{id}/metadata`` returns every table (built-in and
custom ``*_CL``) with its columns. The result is cached per
``(tenant_key, workspace_id)`` for the lifetime of the process — schemas
change on the order of days, and one fetch per boot keeps the
``validate_kql_against_schema`` round-trip cheap.

The metadata body is treated with the same (lack of) trust as query rows:
it is parsed defensively, and only the table *count* is audited — custom
table names can themselves be sensitive.
"""

from __future__ import annotations

import asyncio
from typing import Any

from .audit import audit
from .errors import UpstreamError
from .sentinel_client import SentinelClient
from .validation import TABLE_NAME_PATTERN

WorkspaceSchema = dict[str, dict[str, str]]

_cache: dict[tuple[str, str], WorkspaceSchema] = {}
_locks: dict[tuple[str, str], asyncio.Lock] = {}


def clear_cache() -> None:
    """Drop every cached schema (tests, or a future refresh tool)."""
    _cache.clear()
    _locks.clear()


def parse_metadata(payload: dict[str, Any]) -> WorkspaceSchema:
    """Extract ``{table: {column: type}}`` from a metadata API response.

    Entries with names that are not legal KQL identifiers are dropped rather
    than trusted.
    """
    tables_raw = payload.get("tables")
    if not isinstance(tables_raw, list):
        raise UpstreamError("Log Analytics metadata response had no 'tables' list")
    schema: WorkspaceSchema = {}
    for table in tables_raw:
        if not isinstance(table, dict):
            continue
        name = table.get("name")
        if not isinstance(name, str) or not TABLE_NAME_PATTERN.match(name):
            continue
        columns: dict[str, str] = {}
        for col in table.get("columns") or []:
            if not isinstance(col, dict):
                continue
            col_name = col.get("name")
            if isinstance(col_name, str) and TABLE_NAME_PATTERN.match(col_name):
                columns[col_name] = str(col.get("type", ""))
        schema[name] = columns
    return schema


async def get_live_schema(client: SentinelClient) -> tuple[WorkspaceSchema, bool]:
    """Return ``(schema, cache_hit)`` for the client's workspace."""
    key = (client.tenant_key, client.workspace_id)
    cached = _cache.get(key)
    if cached is not None:
        return cached, True
    lock = _locks.setdefault(key, asyncio.Lock())
    async with lock:
        cached = _cache.get(key)
        if cached is not None:
            return cached, True
        payload = await client.metadata()
        schema = parse_metadata(payload)
        _cache[key] = schema
        audit("schema-fetched", tenant=client.tenant_key, table_count=len(schema))
        return schema, False
