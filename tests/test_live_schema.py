"""Tests for live workspace schema validation (#1)."""

from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest

from mcp_sentinel_detection_engine import live_schema
from mcp_sentinel_detection_engine.errors import SchemaValidationError, UpstreamError
from mcp_sentinel_detection_engine.tools import validate_kql

_METADATA = {
    "tables": [
        {
            "id": "t1",
            "name": "SecurityEvent",
            "columns": [
                {"name": "EventID", "type": "int"},
                {"name": "Account", "type": "string"},
                {"name": "TimeGenerated", "type": "datetime"},
            ],
        },
        {
            "id": "t2",
            "name": "Contoso_Secret_CL",
            "columns": [{"name": "Payload_s", "type": "string"}],
        },
        {"name": "bad name; drop", "columns": []},
        "not-a-dict",
    ]
}


@pytest.fixture(autouse=True)
def _clear_schema_cache() -> Iterator[None]:
    live_schema.clear_cache()
    yield
    live_schema.clear_cache()


def test_parse_metadata_drops_illegal_names() -> None:
    schema = live_schema.parse_metadata(_METADATA)
    assert set(schema) == {"SecurityEvent", "Contoso_Secret_CL"}
    assert schema["SecurityEvent"]["EventID"] == "int"


def test_parse_metadata_rejects_bad_shape() -> None:
    with pytest.raises(UpstreamError):
        live_schema.parse_metadata({"nope": 1})


async def test_omitted_tenant_uses_bundled_snapshot_without_network() -> None:
    result = await validate_kql.run(
        ctx=None,  # type: ignore[arg-type]
        raw_params={"query": "SecurityEvent | where EventID == 4625", "table": "SecurityEvent"},
    )
    assert result["metadata"]["schema_source"] == "bundled"
    assert result["metadata"]["snapshot_date"]


async def test_live_schema_validates_custom_table_and_caches(make_multi_tenant_context) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        assert request.method == "GET"
        return httpx.Response(200, json=_METADATA)

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        params = {
            "query": "Contoso_Secret_CL | where Payload_x == 1",
            "table": "Contoso_Secret_CL",
            "tenant": "contoso",
        }
        first = await validate_kql.run(ctx, params)
        second = await validate_kql.run(ctx, params)

    assert first["valid"] is False
    assert first["unknown_columns"] == ["Payload_x"]
    assert first["suggestions"] == {"Payload_x": ["Payload_s"]}
    assert first["metadata"]["schema_source"] == "live"
    assert first["metadata"]["schema_cache_hit"] is False
    assert second["metadata"]["schema_cache_hit"] is True
    assert calls == ["/v1/workspaces/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/metadata"]


async def test_live_schema_unknown_table_does_not_leak_table_names(
    make_multi_tenant_context,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_METADATA)

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        with pytest.raises(SchemaValidationError) as exc_info:
            await validate_kql.run(
                ctx, {"query": "Nope | take 1", "table": "Nope", "tenant": "contoso"}
            )
    assert "Contoso_Secret_CL" not in str(exc_info.value)


async def test_live_schema_fan_out_fetches_each_tenant(make_multi_tenant_context) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if "bbbbbbbb" in request.url.path:
            return httpx.Response(200, json={"tables": []})
        return httpx.Response(200, json=_METADATA)

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        result = await validate_kql.run(
            ctx,
            {
                "query": "SecurityEvent | where EventID == 1",
                "table": "SecurityEvent",
                "tenant": "*",
            },
        )

    assert result["fan_out"] is True
    assert len(seen) == 2
    by_tenant = {r["tenant"]: r for r in result["results"]}
    assert by_tenant["contoso"]["result"]["valid"] is True
    assert by_tenant["fabrikam"]["error"]["code"] == "schema_validation_error"
