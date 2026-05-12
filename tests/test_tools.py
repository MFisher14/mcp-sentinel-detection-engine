"""Tests for the four tool implementations, the runtime, and server dispatch."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import httpx
import pytest

from mcp_sentinel_detection_engine.errors import (
    AuthError,
    InvalidInputError,
    RateLimitedError,
    SchemaValidationError,
    UpstreamError,
)
from mcp_sentinel_detection_engine.tools import (
    convert_sigma,
    dry_run,
    emit_terraform,
    validate_kql,
)

# A real-shape Sigma rule for the convert tool.
_SIGMA_RULE = """
title: Failed Network Logon
id: 36e037c4-c177-4b35-aff7-9a9c4a9a8b91
status: test
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 3
  condition: selection
level: medium
"""


# ---------- convert_sigma_to_kql ----------


async def test_convert_inline_yaml() -> None:
    result = await convert_sigma.run(ctx=None, raw_params={"sigma_yaml": _SIGMA_RULE})  # type: ignore[arg-type]
    assert result["metadata"]["query_count"] == 1
    assert result["queries"][0]["target_table"] == "SecurityEvent"
    assert "EventID" in result["queries"][0]["kql"]


async def test_convert_from_path(tmp_path: Path) -> None:
    rule = tmp_path / "rule.yaml"
    rule.write_text(_SIGMA_RULE, encoding="utf-8")
    result = await convert_sigma.run(ctx=None, raw_params={"sigma_path": str(rule)})  # type: ignore[arg-type]
    assert result["queries"][0]["target_table"] == "SecurityEvent"


async def test_convert_rejects_relative_path() -> None:
    with pytest.raises(InvalidInputError):
        await convert_sigma.run(ctx=None, raw_params={"sigma_path": "relative/path.yaml"})  # type: ignore[arg-type]


async def test_convert_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(InvalidInputError):
        await convert_sigma.run(
            ctx=None,  # type: ignore[arg-type]
            raw_params={"sigma_path": str(tmp_path / "does-not-exist.yaml")},
        )


async def test_convert_rejects_missing_inputs() -> None:
    with pytest.raises(InvalidInputError):
        await convert_sigma.run(ctx=None, raw_params={})  # type: ignore[arg-type]


# ---------- validate_kql_against_schema ----------


async def test_validate_valid_query() -> None:
    result = await validate_kql.run(
        ctx=None,  # type: ignore[arg-type]
        raw_params={
            "query": "SecurityEvent | where EventID == 4625 | project EventID, Account",
            "table": "SecurityEvent",
        },
    )
    assert result["valid"] is True
    assert result["unknown_columns"] == []


async def test_validate_flags_unknown_column() -> None:
    result = await validate_kql.run(
        ctx=None,  # type: ignore[arg-type]
        raw_params={
            "query": "SecurityEvent | where TotallyMadeUpColumn == 'x'",
            "table": "SecurityEvent",
        },
    )
    assert result["valid"] is False
    assert "TotallyMadeUpColumn" in result["unknown_columns"]


async def test_validate_offers_suggestions_for_typos() -> None:
    result = await validate_kql.run(
        ctx=None,  # type: ignore[arg-type]
        raw_params={
            "query": "SecurityEvent | where AccontName == 'admin'",
            "table": "SecurityEvent",
        },
    )
    assert result["valid"] is False
    # difflib should map "AccontName" → "AccountName"
    suggestions = result["suggestions"].get("AccontName", [])
    assert "AccountName" in suggestions


async def test_validate_unknown_table_errors() -> None:
    with pytest.raises(SchemaValidationError):
        await validate_kql.run(
            ctx=None,  # type: ignore[arg-type]
            raw_params={"query": "X | take 1", "table": "NotARealTable"},
        )


async def test_validate_rejects_destructive_query() -> None:
    with pytest.raises(InvalidInputError):
        await validate_kql.run(
            ctx=None,  # type: ignore[arg-type]
            raw_params={"query": ".drop table foo", "table": "SecurityEvent"},
        )


# ---------- generate_sentinel_terraform ----------


async def test_emit_terraform_full() -> None:
    result = await emit_terraform.run(
        ctx=None,  # type: ignore[arg-type]
        raw_params={
            "query": "SecurityEvent | where EventID == 4625",
            "metadata": {
                "name": "failed_logon",
                "display_name": "Failed Logon",
                "severity": "High",
                "tactics": ["CredentialAccess"],
                "techniques": ["T1110"],
            },
        },
    )
    hcl = result["terraform_hcl"]
    assert 'resource "azurerm_sentinel_alert_rule_scheduled" "failed_logon"' in hcl
    assert result["metadata"]["severity"] == "High"


async def test_emit_terraform_rejects_bad_tactic() -> None:
    with pytest.raises(InvalidInputError):
        await emit_terraform.run(
            ctx=None,  # type: ignore[arg-type]
            raw_params={
                "query": "SecurityEvent | take 1",
                "metadata": {
                    "name": "r",
                    "display_name": "x",
                    "tactics": ["lowercase_tactic"],
                },
            },
        )


# ---------- dry_run_kql ----------


async def test_dry_run_success(make_context) -> None:
    received: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        received["path"] = request.url.path
        received["method"] = request.method
        received["auth"] = request.headers.get("Authorization")
        return httpx.Response(
            200,
            json={
                "tables": [
                    {
                        "name": "PrimaryResult",
                        "columns": [
                            {"name": "TimeGenerated", "type": "datetime"},
                            {"name": "EventID", "type": "int"},
                        ],
                        "rows": [["2026-05-01T00:00:00Z", 4625]],
                    }
                ]
            },
        )

    ctx, _ = make_context(handler)
    async with ctx:
        result = await dry_run.run(
            ctx, {"query": "SecurityEvent | where EventID == 4625", "timespan": "PT1H"}
        )

    assert received["method"] == "POST"
    assert "/v1/workspaces/" in received["path"]
    assert received["path"].endswith("/query")
    assert received["auth"].startswith("Bearer ")
    assert result["metadata"]["row_count"] == 1
    assert result["metadata"]["column_count"] == 2


async def test_dry_run_clamps_to_row_limit(make_context) -> None:
    received_body: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        received_body.update(json.loads(request.content.decode("utf-8")))
        return httpx.Response(200, json={"tables": []})

    ctx, _ = make_context(handler)
    async with ctx:
        await dry_run.run(
            ctx,
            {"query": "SecurityEvent", "row_limit": 5},
        )

    assert "take 5" in received_body["query"]


async def test_dry_run_rejects_destructive(make_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("upstream must not be called for invalid input")

    ctx, _ = make_context(handler)
    async with ctx:
        with pytest.raises(InvalidInputError):
            await dry_run.run(ctx, {"query": ".drop table foo"})


async def test_dry_run_oversized_query_rejected(make_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("upstream must not be called")

    ctx, _ = make_context(handler)
    async with ctx:
        with pytest.raises(InvalidInputError):
            await dry_run.run(ctx, {"query": "x" * 10_001})


# ---------- sentinel_client error handling ----------


async def test_rate_limit_retries_then_succeeds(make_context) -> None:
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        if call_count["n"] <= 2:
            return httpx.Response(429, headers={"Retry-After": "1"}, json={})
        return httpx.Response(200, json={"tables": []})

    ctx, sleeps = make_context(handler)
    async with ctx:
        result = await dry_run.run(ctx, {"query": "SecurityEvent | take 1"})

    assert call_count["n"] == 3
    assert len(sleeps) == 2
    assert all(s == 1.0 for s in sleeps)
    assert result["metadata"]["row_count"] == 0


async def test_rate_limit_exhausts_retries(make_context) -> None:
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(429, headers={"Retry-After": "0"}, json={})

    ctx, _ = make_context(handler)
    async with ctx:
        with pytest.raises(RateLimitedError):
            await dry_run.run(ctx, {"query": "SecurityEvent | take 1"})
    assert call_count["n"] == 4


async def test_server_error_retried_then_raised(make_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={})

    ctx, _ = make_context(handler)
    async with ctx:
        with pytest.raises(UpstreamError):
            await dry_run.run(ctx, {"query": "SecurityEvent | take 1"})


async def test_401_refreshes_token_once(make_context, fake_msal_app) -> None:
    fake_msal_app.results = [
        {"access_token": "stale", "expires_in": 3600},
        {"access_token": "fresh", "expires_in": 3600},
    ]
    tokens_seen: list[str] = []
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        tokens_seen.append(request.headers.get("Authorization", ""))
        call_count["n"] += 1
        if call_count["n"] == 1:
            return httpx.Response(401, json={"error": "expired"})
        return httpx.Response(200, json={"tables": []})

    ctx, _ = make_context(handler)
    async with ctx:
        await dry_run.run(ctx, {"query": "SecurityEvent | take 1"})

    assert tokens_seen[0] == "Bearer stale"
    assert tokens_seen[1] == "Bearer fresh"


async def test_persistent_401_becomes_auth_error(make_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "expired"})

    ctx, _ = make_context(handler)
    async with ctx:
        with pytest.raises(AuthError):
            await dry_run.run(ctx, {"query": "SecurityEvent | take 1"})


# ---------- server-level dispatch ----------


async def test_server_dispatch_maps_known_error(make_context) -> None:
    from mcp_sentinel_detection_engine.errors import ErrorCode
    from mcp_sentinel_detection_engine.server import _dispatch

    async def failing_handler(ctx, params):
        raise InvalidInputError("bad input")

    ctx, _ = make_context(lambda r: httpx.Response(500))
    async with ctx:
        result = await _dispatch(failing_handler, ctx, {}, "x")

    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == ErrorCode.INVALID_INPUT.value


async def test_server_dispatch_maps_unhandled_to_internal(make_context) -> None:
    from mcp_sentinel_detection_engine.errors import ErrorCode
    from mcp_sentinel_detection_engine.server import _dispatch

    async def boom(ctx, params):
        raise RuntimeError("internal detail with secret token-xyz")

    ctx, _ = make_context(lambda r: httpx.Response(500))
    async with ctx:
        result = await _dispatch(boom, ctx, {}, "x")

    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == ErrorCode.INTERNAL_ERROR.value
    assert "token-xyz" not in result.structuredContent["error"]["message"]


# ---------- multi-tenant + fan-out (dry_run_kql) ----------


async def test_explicit_tenant_routes_to_right_credentials(make_multi_tenant_context) -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Authorization", "")
        seen["path"] = request.url.path
        return httpx.Response(200, json={"tables": []})

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        await dry_run.run(ctx, {"query": "SecurityEvent | take 1", "tenant": "fabrikam"})

    assert seen["auth"] == "Bearer token-fabrikam"
    assert "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" in seen["path"]


async def test_default_tenant_when_omitted(make_multi_tenant_context) -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Authorization", "")
        return httpx.Response(200, json={"tables": []})

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        await dry_run.run(ctx, {"query": "SecurityEvent | take 1"})

    assert seen["auth"] == "Bearer token-contoso"


async def test_unknown_explicit_tenant_rejected(make_multi_tenant_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("upstream must not be called")

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        with pytest.raises(InvalidInputError) as exc_info:
            await dry_run.run(ctx, {"query": "SecurityEvent | take 1", "tenant": "ghost-tenant"})
    assert "ghost-tenant" not in str(exc_info.value)


async def test_fan_out_aggregates_per_tenant(make_multi_tenant_context) -> None:
    seen_tokens: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_tokens.append(request.headers.get("Authorization", ""))
        return httpx.Response(
            200,
            json={
                "tables": [
                    {
                        "name": "PrimaryResult",
                        "columns": [{"name": "X", "type": "int"}],
                        "rows": [[1]],
                    }
                ]
            },
        )

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        result = await dry_run.run(ctx, {"query": "SecurityEvent | take 1", "tenant": "*"})

    assert result["fan_out"] is True
    assert sorted(result["tenants"]) == ["contoso", "fabrikam"]
    assert len(result["results"]) == 2
    by_tenant = {r["tenant"]: r for r in result["results"]}
    assert "result" in by_tenant["contoso"]
    assert "result" in by_tenant["fabrikam"]
    assert sorted(seen_tokens) == sorted(["Bearer token-contoso", "Bearer token-fabrikam"])


async def test_fan_out_partial_failure(make_multi_tenant_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if "fabrikam" in auth:
            return httpx.Response(503, json={})
        return httpx.Response(200, json={"tables": []})

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        result = await dry_run.run(ctx, {"query": "SecurityEvent | take 1", "tenant": "*"})

    by_tenant = {r["tenant"]: r for r in result["results"]}
    assert "result" in by_tenant["contoso"]
    assert "error" in by_tenant["fabrikam"]
    assert by_tenant["fabrikam"]["error"]["code"] == "upstream_error"


async def test_fan_out_unhandled_exception_per_tenant(
    make_multi_tenant_context, monkeypatch
) -> None:
    """A non-SentinelError raised inside the per-tenant call surfaces as internal_error."""
    call_count = {"n": 0}

    real_shape = dry_run._shape_response

    def flaky_shape(payload):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise RuntimeError("kaboom")
        return real_shape(payload)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"tables": []})

    monkeypatch.setattr(dry_run, "_shape_response", flaky_shape)

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        result = await dry_run.run(ctx, {"query": "SecurityEvent | take 1", "tenant": "*"})

    by_tenant = {r["tenant"]: r for r in result["results"]}
    errors = [t for t, r in by_tenant.items() if "error" in r]
    oks = [t for t, r in by_tenant.items() if "result" in r]
    assert len(errors) == 1
    assert len(oks) == 1
    assert by_tenant[errors[0]]["error"]["code"] == "internal_error"


async def test_fan_out_respects_max_fan_out(make_multi_tenant_context) -> None:
    in_flight = 0
    max_in_flight = 0
    lock = asyncio.Lock()

    async def gate_handler(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, max_in_flight
        async with lock:
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.01)
        async with lock:
            in_flight -= 1
        return httpx.Response(200, json={"tables": []})

    ctx, _ = make_multi_tenant_context(gate_handler, max_fan_out=1)
    async with ctx:
        result = await dry_run.run(ctx, {"query": "SecurityEvent | take 1", "tenant": "*"})

    assert len(result["results"]) == 2
    assert max_in_flight == 1
