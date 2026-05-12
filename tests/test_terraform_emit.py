"""Tests for Terraform HCL emission."""

from __future__ import annotations

from mcp_sentinel_detection_engine.terraform_emit import emit_terraform
from mcp_sentinel_detection_engine.validation import (
    Severity,
    TerraformRuleMetadata,
)


def _metadata(**overrides: object) -> TerraformRuleMetadata:
    base: dict[str, object] = {
        "name": "failed_logon_burst",
        "display_name": "Failed Logon Burst",
        "description": "Multiple failed Windows logons in a short window.",
        "severity": Severity.HIGH,
        "tactics": ["CredentialAccess"],
        "techniques": ["T1110", "T1110.001"],
    }
    base.update(overrides)
    return TerraformRuleMetadata(**base)  # type: ignore[arg-type]


def test_emits_expected_resource_block() -> None:
    hcl = emit_terraform("SecurityEvent\n| where EventID == 4625", _metadata())
    assert 'resource "azurerm_sentinel_alert_rule_scheduled" "failed_logon_burst"' in hcl
    assert "log_analytics_workspace_id = var.log_analytics_workspace_id" in hcl
    assert 'display_name               = "Failed Logon Burst"' in hcl
    assert 'severity                   = "High"' in hcl
    assert 'tactics                    = ["CredentialAccess"]' in hcl
    assert 'techniques                 = ["T1110", "T1110.001"]' in hcl
    assert "SecurityEvent" in hcl
    assert "EventID == 4625" in hcl


def test_emitted_query_uses_heredoc() -> None:
    hcl = emit_terraform("SecurityEvent | take 5", _metadata())
    assert "<<-EOT" in hcl
    assert "  EOT" in hcl


def test_double_quotes_in_description_are_escaped() -> None:
    hcl = emit_terraform(
        "SecurityEvent | take 1",
        _metadata(description='Has "quotes" and ${var.naughty}'),
    )
    # raw double-quote inside an HCL string literal must be escaped
    assert '\\"quotes\\"' in hcl
    # template interpolation must be neutralized
    assert "$${var.naughty}" in hcl


def test_resource_name_is_deterministic_per_input_name() -> None:
    hcl_a = emit_terraform("SecurityEvent | take 1", _metadata(name="rule_one"))
    hcl_b = emit_terraform("SecurityEvent | take 1", _metadata(name="rule_one"))
    hcl_c = emit_terraform("SecurityEvent | take 1", _metadata(name="rule_two"))

    # extract the inner name = "<uuid>" line
    def _uuid_of(blob: str) -> str:
        for line in blob.splitlines():
            stripped = line.strip()
            if stripped.startswith("name") and "=" in stripped:
                return stripped.split("=", 1)[1].strip().strip('"')
        raise AssertionError("name not found")

    assert _uuid_of(hcl_a) == _uuid_of(hcl_b)
    assert _uuid_of(hcl_a) != _uuid_of(hcl_c)


def test_empty_lists_render_as_empty_arrays() -> None:
    hcl = emit_terraform(
        "SecurityEvent | take 1",
        _metadata(tactics=[], techniques=[]),
    )
    assert "tactics                    = []" in hcl
    assert "techniques                 = []" in hcl
