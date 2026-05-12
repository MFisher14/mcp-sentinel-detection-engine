"""Tests for the Sigma → KQL conversion pipeline.

Uses real Sigma rule shapes drawn from public SigmaHQ patterns. Conversion is a
pure function with no Azure dependency.
"""

from __future__ import annotations

import pytest

from mcp_sentinel_detection_engine.errors import ConversionError
from mcp_sentinel_detection_engine.sigma_pipeline import convert_sigma

# A simple Windows Security 4625 (failed logon) rule — maps to SecurityEvent.
_FAILED_LOGON_RULE = """
title: Failed Network Logon
id: 36e037c4-c177-4b35-aff7-9a9c4a9a8b91
status: test
description: Detect failed Windows network logons (EventID 4625, LogonType 3).
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

# An Entra ID sign-in rule — should target SigninLogs.
_RISKY_SIGNIN_RULE = """
title: Risky Sign-in
id: 5fb1c2e5-1f7d-46f8-9b89-0e9c3b53cf60
status: test
description: Sign-ins with aggregate risk level high.
logsource:
  product: azure
  service: signinlogs
detection:
  selection:
    RiskLevelAggregated: high
  condition: selection
level: high
"""


def test_converts_windows_security_to_security_event() -> None:
    results = convert_sigma(_FAILED_LOGON_RULE)
    assert len(results) == 1
    assert results[0].target_table == "SecurityEvent"
    assert "EventID" in results[0].kql
    assert "4625" in results[0].kql
    assert "LogonType" in results[0].kql


def test_converts_signinlogs_rule_with_explicit_target() -> None:
    """SigninLogs has no built-in azure_monitor logsource mapping; caller must
    pass ``target_table``. This is documented in convert_sigma's docstring and
    surfaced in the tool description so Claude knows when to provide it."""
    results = convert_sigma(_RISKY_SIGNIN_RULE, target_table="SigninLogs")
    assert len(results) == 1
    assert results[0].target_table == "SigninLogs"
    assert "RiskLevelAggregated" in results[0].kql or "RiskLevel" in results[0].kql


def test_signinlogs_rule_without_target_raises_conversion_error() -> None:
    """Honest surfacing: without ``target_table`` the pipeline cannot infer
    SigninLogs from a generic Azure logsource and we must error cleanly."""
    with pytest.raises(ConversionError) as exc_info:
        convert_sigma(_RISKY_SIGNIN_RULE)
    assert "table" in str(exc_info.value).lower()


def test_rejects_malformed_yaml() -> None:
    with pytest.raises(ConversionError):
        convert_sigma(":\n  : invalid yaml structure :::")


def test_rejects_empty_collection() -> None:
    with pytest.raises(ConversionError):
        convert_sigma("")


def test_rejects_unmappable_logsource() -> None:
    """A logsource the azure_monitor pipeline can't map should error out cleanly."""
    bad_rule = """
title: Mystery
id: 11111111-2222-3333-4444-555555555555
status: test
logsource:
  product: nonexistent-product
  service: nonexistent-service
detection:
  selection:
    Field: value
  condition: selection
level: low
"""
    with pytest.raises(ConversionError):
        convert_sigma(bad_rule)
