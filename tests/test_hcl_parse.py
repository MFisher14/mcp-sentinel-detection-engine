"""Tests for the strict HCL-subset parser."""

from __future__ import annotations

import pytest

from mcp_sentinel_detection_engine.errors import InvalidInputError
from mcp_sentinel_detection_engine.hcl_parse import VariableRef, parse_rules

GOOD = """# checked in
resource "azurerm_sentinel_alert_rule_scheduled" "failed_logon" {
  log_analytics_workspace_id = var.log_analytics_workspace_id
  name                       = "6f1c0e8a-1111-5222-8333-444455556666"
  display_name               = "Failed \\"logon\\" burst"
  enabled                    = true
  trigger_threshold          = 10
  tactics                    = ["CredentialAccess", "InitialAccess",]
  techniques                 = []
  query                      = <<-EOT
    SecurityEvent
      | where EventID == 4625
  EOT
}

resource "azurerm_sentinel_alert_rule_scheduled" "second" {
  display_name = "Two"
  raw          = <<RAW
  kept indent
RAW
}
"""


def test_parses_emitted_subset() -> None:
    first, second = parse_rules(GOOD)
    assert first.resource_name == "failed_logon"
    attrs = first.attributes
    assert attrs["log_analytics_workspace_id"] == VariableRef("var.log_analytics_workspace_id")
    assert attrs["display_name"] == 'Failed "logon" burst'
    assert attrs["enabled"] is True
    assert attrs["trigger_threshold"] == 10
    assert attrs["tactics"] == ["CredentialAccess", "InitialAccess"]
    assert attrs["techniques"] == []
    assert attrs["query"] == "SecurityEvent\n  | where EventID == 4625"
    assert second.attributes["raw"] == "  kept indent"


def test_escaped_template_sequences_unescape() -> None:
    hcl = (
        'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n'
        '  description = "literal $${var.y} and %%{if}"\n'
        "}\n"
    )
    (rule,) = parse_rules(hcl)
    assert rule.attributes["description"] == "literal ${var.y} and %{if}"


@pytest.mark.parametrize(
    ("hcl", "match"),
    [
        ('resource "null_resource" "x" {\n}\n', "not allowed"),
        ('data "external" "x" {\n}\n', "only `resource"),
        ('module "m" {\n}\n', "only `resource"),
        ("locals {\n}\n", "only `resource"),
        (
            'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n'
            '  provisioner "local-exec" {\n    command = "id"\n  }\n}\n',
            "nested blocks",
        ),
        (
            'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n'
            '  description = "${file("/etc/passwd")}"\n}\n',
            "template",
        ),
        (
            'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n'
            '  query = <<-EOT\n    ${file("/etc/passwd")}\n  EOT\n}\n',
            "template",
        ),
        (
            'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n'
            '  description = "%{ for x in y }"\n}\n',
            "template",
        ),
        (
            'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n'
            '  description = file("/etc/passwd")\n}\n',
            "unsupported value",
        ),
        (
            'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n'
            "  description = var.other\n}\n",
            "unsupported value",
        ),
        (
            'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n  a = "1"\n  a = "2"\n}\n',
            "duplicate attribute",
        ),
        (
            'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n}\n'
            'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n}\n',
            "duplicate resource",
        ),
        ('resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n  a = "1"\n', "unterminated"),
        (
            'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n  q = <<-EOT\n  x\n}\n',
            "unterminated heredoc",
        ),
        ('resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n  a = "x\n}\n', "unterminated"),
        (
            'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n  a = "x" "y"\n}\n',
            "after string",
        ),
        (
            'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n  a = "\\q"\n}\n',
            "unsupported escape",
        ),
        (
            'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n  a = ["x" "y"]\n}\n',
            "separated by commas",
        ),
        (
            'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n  a = [x]\n}\n',
            "double-quoted",
        ),
        ("# only a comment\n", "no azurerm_sentinel_alert_rule_scheduled"),
        ("x" * 200_001, "exceeds"),
        ("a\x00b", "NUL"),
    ],
)
def test_rejects_outside_subset(hcl: str, match: str) -> None:
    with pytest.raises(InvalidInputError, match=match):
        parse_rules(hcl)
