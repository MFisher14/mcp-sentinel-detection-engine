"""Tests for ``list_deployed_sentinel_rules``."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from mcp_sentinel_detection_engine.errors import InvalidInputError
from mcp_sentinel_detection_engine.tools import list_rules


def _rule(
    guid: str,
    display: str,
    *,
    severity: str = "High",
    enabled: bool = True,
    kind: str = "Scheduled",
) -> dict[str, Any]:
    return {
        "id": f"/subscriptions/x/.../alertRules/{guid}",
        "name": guid,
        "kind": kind,
        "properties": {
            "displayName": display,
            "severity": severity,
            "enabled": enabled,
            "lastModifiedUtc": "2026-05-01T00:00:00Z",
            "query": "SecurityEvent",
        },
    }


RULES = [
    _rule("r1", "Failed logon burst"),
    _rule("r2", "Risky sign-in", severity="Medium", enabled=False),
    _rule("r3", "Fusion", kind="Fusion", severity="High"),
]


def _handler(rules: list[dict[str, Any]], seen: list[httpx.Request] | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return httpx.Response(200, json={"value": rules})

    return handler


async def test_list_rules_summarizes(make_mgmt_context) -> None:
    seen: list[httpx.Request] = []
    ctx = make_mgmt_context(_handler(RULES, seen))
    result = await list_rules.run(ctx, {})
    assert result["metadata"]["returned_count"] == 3
    assert result["rules"][0] == {
        "id": "/subscriptions/x/.../alertRules/r1",
        "name": "r1",
        "display_name": "Failed logon burst",
        "severity": "High",
        "enabled": True,
        "kind": "Scheduled",
        "last_modified": "2026-05-01T00:00:00Z",
    }
    assert "query" not in result["rules"][0]
    assert "/resourceGroups/rg-contoso/" in seen[0].url.path
    assert seen[0].headers["Authorization"] == "Bearer token-1"
    await ctx.aclose()


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"enabled": False}, ["r2"]),
        ({"severity": "High"}, ["r1", "r3"]),
        ({"kind": "Fusion"}, ["r3"]),
        ({"severity": "High", "kind": "Scheduled"}, ["r1"]),
        ({"limit": 2}, ["r1", "r2"]),
    ],
)
async def test_list_rules_filters(make_mgmt_context, params, expected) -> None:
    ctx = make_mgmt_context(_handler(RULES))
    result = await list_rules.run(ctx, params)
    assert [r["name"] for r in result["rules"]] == expected
    await ctx.aclose()


async def test_list_rules_truncated_flag(make_mgmt_context) -> None:
    ctx = make_mgmt_context(_handler(RULES))
    result = await list_rules.run(ctx, {"severity": "High", "limit": 1})
    assert result["metadata"]["truncated"] is True
    await ctx.aclose()


async def test_list_rules_rejects_bad_kind(make_mgmt_context) -> None:
    ctx = make_mgmt_context(_handler(RULES))
    with pytest.raises(InvalidInputError):
        await list_rules.run(ctx, {"kind": "Bogus"})
    await ctx.aclose()


async def test_list_rules_unconfigured_tenant(make_mgmt_context) -> None:
    ctx = make_mgmt_context(_handler(RULES), include_bare=True)
    with pytest.raises(InvalidInputError, match="management-plane"):
        await list_rules.run(ctx, {"tenant": "bare"})
    await ctx.aclose()


async def test_list_rules_fan_out(make_mgmt_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "rg-fabrikam" in request.url.path:
            return httpx.Response(200, json={"value": [_rule("f1", "Fab rule")]})
        return httpx.Response(200, json={"value": RULES})

    ctx = make_mgmt_context(handler, include_bare=True)
    result = await list_rules.run(ctx, {"tenant": "*"})
    by_tenant = {r["tenant"]: r for r in result["results"]}
    assert [x["name"] for x in by_tenant["fabrikam"]["result"]["rules"]] == ["f1"]
    assert by_tenant["contoso"]["result"]["metadata"]["returned_count"] == 3
    assert by_tenant["bare"]["error"]["code"] == "invalid_input"
    await ctx.aclose()


async def test_list_rules_ignores_malformed_items(make_mgmt_context) -> None:
    ctx = make_mgmt_context(_handler([{"name": 5, "properties": "x"}]))
    result = await list_rules.run(ctx, {})
    assert result["rules"][0]["name"] is None
    assert result["rules"][0]["enabled"] is None
    await ctx.aclose()
