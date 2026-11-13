"""Tests for ``link_hunt_to_rule``."""

from __future__ import annotations

import pytest
from sigma.collection import SigmaCollection

from mcp_sentinel_detection_engine.errors import InvalidInputError
from mcp_sentinel_detection_engine.sigma_pipeline import convert_sigma
from mcp_sentinel_detection_engine.tools import link_hunt

PROCESS_HUNT = """DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-EncodedCommand"
| where InitiatingProcessFileName in ("winword.exe", "excel.exe")
| project Timestamp, DeviceName, ProcessCommandLine"""

SIGNIN_HUNT = """AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 50126 and AccountUpn endswith "@contoso.com"
| where Application == "Timestamp in a string stays"
| summarize count() by AccountUpn, IPAddress"""


async def test_process_hunt_keeps_table_and_renames_timestamp() -> None:
    result = await link_hunt.run(None, {"query": PROCESS_HUNT})  # type: ignore[arg-type]
    assert result["source_tables"] == ["DeviceProcessEvents"]
    assert result["target_tables"] == ["DeviceProcessEvents"]
    assert "Timestamp" not in result["sentinel_query"]
    assert "TimeGenerated > ago(1d)" in result["sentinel_query"]
    assert "Defender XDR connector" in result["table_mappings"][0]["note"]
    assert {"source": "Timestamp", "target": "TimeGenerated"} in result["column_mappings"]


async def test_process_hunt_sigma_skeleton_is_valid_and_converts() -> None:
    result = await link_hunt.run(
        None,  # type: ignore[arg-type]
        {"query": PROCESS_HUNT, "title": "Office spawning encoded PowerShell"},
    )
    skeleton = result["sigma_skeleton"]
    collection = SigmaCollection.from_yaml(skeleton)
    rule = collection.rules[0]
    assert rule.title == "Office spawning encoded PowerShell"
    assert rule.status.name.lower() == "experimental"
    assert rule.logsource.category == "process_creation"
    assert "Image|endswith" in skeleton
    assert "CommandLine|contains" in skeleton
    assert '"winword.exe"' in skeleton
    (converted,) = convert_sigma(skeleton)
    assert "powershell.exe" in converted.kql


async def test_signin_hunt_retargets_table_and_columns() -> None:
    result = await link_hunt.run(None, {"query": SIGNIN_HUNT})  # type: ignore[arg-type]
    q = result["sentinel_query"]
    assert q.startswith("SigninLogs")
    assert "UserPrincipalName endswith" in q
    assert "ResultType == 50126" in q
    assert "AppDisplayName ==" in q
    # String literals are never rewritten.
    assert '"Timestamp in a string stays"' in q
    assert result["target_tables"] == ["SigninLogs"]
    targets = {m["source"]: m["target"] for m in result["column_mappings"]}
    assert targets["AccountUpn"] == "UserPrincipalName"
    skeleton = SigmaCollection.from_yaml(result["sigma_skeleton"]).rules[0]
    assert skeleton.logsource.service == "signinlogs"


async def test_unknown_table_and_no_predicates_warn() -> None:
    result = await link_hunt.run(None, {"query": "MyCustom_CL | take 10"})  # type: ignore[arg-type]
    assert result["source_tables"] == []
    assert len(result["warnings"]) == 2
    assert "TODO_Field" in result["sigma_skeleton"]
    SigmaCollection.from_yaml(result["sigma_skeleton"])


async def test_table_without_sigma_logsource_warns() -> None:
    result = await link_hunt.run(
        None,  # type: ignore[arg-type]
        {"query": 'EmailEvents | where SenderFromDomain == "evil.example"'},
    )
    assert any("No standard Sigma logsource" in w for w in result["warnings"])
    rule = SigmaCollection.from_yaml(result["sigma_skeleton"]).rules[0]
    assert rule.logsource.service == "emailevents"


async def test_injection_in_title_and_values_stays_inert() -> None:
    result = await link_hunt.run(
        None,  # type: ignore[arg-type]
        {
            "query": 'DeviceProcessEvents | where ProcessCommandLine == "x\\"\\nlevel: critical"',
            "title": "t\nlevel: critical‮",
        },
    )
    rule = SigmaCollection.from_yaml(result["sigma_skeleton"]).rules[0]
    assert rule.level.name.lower() == "medium"
    assert rule.title == "t level: critical"


async def test_rejects_destructive_kql() -> None:
    with pytest.raises(InvalidInputError, match="control verb"):
        await link_hunt.run(None, {"query": ".drop table DeviceProcessEvents"})  # type: ignore[arg-type]


async def test_rejects_blank_title() -> None:
    with pytest.raises(InvalidInputError):
        await link_hunt.run(None, {"query": "DeviceEvents", "title": "​ "})  # type: ignore[arg-type]
