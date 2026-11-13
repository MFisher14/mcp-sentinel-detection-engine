"""Tests for ``detect_rule_drift`` and the drift comparison engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from mcp_sentinel_detection_engine.drift import duration_seconds
from mcp_sentinel_detection_engine.errors import InvalidInputError, NotFoundError
from mcp_sentinel_detection_engine.terraform_emit import _stable_rule_uuid, emit_terraform
from mcp_sentinel_detection_engine.tools import detect_drift
from mcp_sentinel_detection_engine.validation import Severity, TerraformRuleMetadata

QUERY = "SecurityEvent\n| where EventID == 4625"
META = TerraformRuleMetadata(
    name="failed_logon",
    display_name="Failed logon burst",
    description="Bursts of failures",
    severity=Severity.HIGH,
    query_frequency="PT1H",
    query_period="P1D",
    trigger_threshold=5,
    tactics=["CredentialAccess"],
    techniques=["T1110"],
)
HCL = emit_terraform(QUERY, META)
GUID = _stable_rule_uuid("failed_logon")


def _live(**overrides: Any) -> dict[str, Any]:
    props: dict[str, Any] = {
        "displayName": "Failed logon burst",
        "description": "Bursts of failures",
        "severity": "High",
        "enabled": True,
        "query": "SecurityEvent\r\n| where EventID == 4625   \n",
        "queryFrequency": "PT60M",
        "queryPeriod": "PT24H",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 5,
        "suppressionEnabled": False,
        "suppressionDuration": "PT1H",
        "tactics": ["CredentialAccess"],
        "techniques": ["T1110"],
    }
    props.update(overrides)
    return {"name": GUID, "kind": "Scheduled", "properties": props}


def _single_rule_handler(rule: dict[str, Any], seen: list[httpx.Request] | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if request.url.path.endswith("/alertRules"):
            return httpx.Response(200, json={"value": [rule]})
        if request.url.path.endswith(f"/alertRules/{rule['name']}"):
            return httpx.Response(200, json=rule)
        return httpx.Response(404, json={})

    return handler


def test_duration_seconds() -> None:
    assert duration_seconds("PT1H") == duration_seconds("PT60M") == 3600
    assert duration_seconds("P1D") == duration_seconds("PT24H")
    assert duration_seconds("P1W") == 604_800
    assert duration_seconds("bogus") is None
    assert duration_seconds("PT") is None


async def test_no_drift_with_equivalent_values(make_mgmt_context) -> None:
    seen: list[httpx.Request] = []
    ctx = make_mgmt_context(_single_rule_handler(_live(), seen))
    result = await detect_drift.run(ctx, {"hcl": HCL})
    assert result["drifted"] is False, result
    assert result["warnings"] == []
    # Defaulted the rule id from the HCL's `name` GUID.
    assert seen[0].url.path.endswith(f"/alertRules/{GUID}")
    await ctx.aclose()


async def test_drift_detects_changes_added_removed(make_mgmt_context) -> None:
    live = _live(
        enabled=False,
        severity="Low",
        query="SecurityEvent | take 1",
        tactics=["CredentialAccess", "Persistence"],
        techniques=None,
        description=None,
        triggerThreshold=5,
    )
    live["properties"]["queryPeriod"] = "P2D"
    ctx = make_mgmt_context(_single_rule_handler(live))
    result = await detect_drift.run(ctx, {"hcl": HCL, "rule_id": GUID})
    assert result["drifted"] is True
    changed = {c["field"]: c for c in result["changed"]}
    assert changed["enabled"]["before"] is True
    assert changed["enabled"]["after"] is False
    assert set(changed) == {"enabled", "severity", "query", "tactics", "query_period"}
    removed = {r["field"] for r in result["removed"]}
    assert removed == {"techniques", "description"}
    assert result["high_priority"] == ["enabled", "query", "severity", "tactics", "techniques"]
    assert changed["query_period"]["high_priority"] is False
    await ctx.aclose()


async def test_drift_reports_added_fields() -> None:
    from mcp_sentinel_detection_engine.drift import compare
    from mcp_sentinel_detection_engine.hcl_parse import ParsedRule

    declared = ParsedRule("azurerm_sentinel_alert_rule_scheduled", "x", {"display_name": "X"})
    report = compare(declared, {"displayName": "X", "enabled": True, "tactics": []})
    assert [a["field"] for a in report.added] == ["enabled"]
    assert report.high_priority == ["enabled"]


async def test_drift_by_name_pattern(make_mgmt_context) -> None:
    ctx = make_mgmt_context(_single_rule_handler(_live(severity="Medium")))
    result = await detect_drift.run(ctx, {"hcl": HCL, "rule_name_pattern": "failed LOGON*"})
    assert result["rule_id"] == GUID
    assert [c["field"] for c in result["changed"]] == ["severity"]
    await ctx.aclose()


async def test_drift_pattern_no_match(make_mgmt_context) -> None:
    ctx = make_mgmt_context(_single_rule_handler(_live()))
    with pytest.raises(NotFoundError):
        await detect_drift.run(ctx, {"hcl": HCL, "rule_name_pattern": "nope*"})
    await ctx.aclose()


async def test_drift_pattern_ambiguous(make_mgmt_context) -> None:
    rules = [_live(), {**_live(), "name": "other"}]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"value": rules})

    ctx = make_mgmt_context(handler)
    with pytest.raises(InvalidInputError, match="matched 2 rules"):
        await detect_drift.run(ctx, {"hcl": HCL, "rule_name_pattern": "*"})
    await ctx.aclose()


async def test_drift_warns_on_kind_and_guid_mismatch(make_mgmt_context) -> None:
    live = {**_live(), "name": "11111111-2222-3333-4444-555555555555", "kind": "NRT"}
    ctx = make_mgmt_context(_single_rule_handler(live))
    result = await detect_drift.run(ctx, {"hcl": HCL, "rule_id": live["name"]})
    assert len(result["warnings"]) == 2
    await ctx.aclose()


async def test_drift_selects_block_from_multi_rule_hcl(make_mgmt_context) -> None:
    other = emit_terraform(
        "SigninLogs", META.model_copy(update={"name": "other", "display_name": "O"})
    )
    ctx = make_mgmt_context(_single_rule_handler(_live()))
    result = await detect_drift.run(ctx, {"hcl": other + HCL, "rule_id": GUID})
    assert result["resource_name"] == "failed_logon"
    assert result["drifted"] is False
    result = await detect_drift.run(
        ctx, {"hcl": other + HCL, "rule_id": GUID, "resource_name": "other"}
    )
    assert result["drifted"] is True
    with pytest.raises(InvalidInputError, match="resource_name not found"):
        await detect_drift.run(ctx, {"hcl": HCL, "rule_id": GUID, "resource_name": "zzz"})
    with pytest.raises(InvalidInputError, match="several rule blocks"):
        await detect_drift.run(ctx, {"hcl": other + HCL})
    await ctx.aclose()


async def test_drift_from_path(make_mgmt_context, tmp_path: Path) -> None:
    tf = tmp_path / "rule.tf"
    tf.write_text(HCL)
    ctx = make_mgmt_context(_single_rule_handler(_live()))
    result = await detect_drift.run(ctx, {"hcl_path": str(tf)})
    assert result["drifted"] is False
    with pytest.raises(InvalidInputError, match="absolute"):
        await detect_drift.run(ctx, {"hcl_path": "rule.tf"})
    with pytest.raises(InvalidInputError, match="does not point"):
        await detect_drift.run(ctx, {"hcl_path": str(tmp_path / "missing.tf")})
    await ctx.aclose()


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"hcl": HCL, "hcl_path": "/x"},
        {"hcl": HCL, "rule_id": "not-a-guid"},
        {"hcl": HCL, "rule_id": GUID, "rule_name_pattern": "x"},
        {"hcl_path": "/a\x00b"},
    ],
)
async def test_drift_input_validation(make_mgmt_context, params) -> None:
    ctx = make_mgmt_context(_single_rule_handler(_live()))
    with pytest.raises(InvalidInputError):
        await detect_drift.run(ctx, params)
    await ctx.aclose()


async def test_drift_requires_guid_when_hcl_has_none(make_mgmt_context) -> None:
    hcl = 'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n  display_name = "X"\n}\n'
    ctx = make_mgmt_context(_single_rule_handler(_live()))
    with pytest.raises(InvalidInputError, match="no GUID"):
        await detect_drift.run(ctx, {"hcl": hcl})
    await ctx.aclose()


async def test_drift_fan_out(make_mgmt_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "rg-fabrikam" in request.url.path:
            return httpx.Response(200, json=_live(enabled=False))
        return httpx.Response(200, json=_live())

    ctx = make_mgmt_context(handler)
    result = await detect_drift.run(ctx, {"hcl": HCL, "tenant": "*"})
    by_tenant = {r["tenant"]: r["result"] for r in result["results"]}
    assert by_tenant["contoso"]["drifted"] is False
    assert by_tenant["fabrikam"]["high_priority"] == ["enabled"]
    await ctx.aclose()
