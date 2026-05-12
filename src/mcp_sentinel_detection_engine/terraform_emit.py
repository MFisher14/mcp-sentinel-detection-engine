"""Emit Terraform HCL for ``azurerm_sentinel_alert_rule_scheduled`` resources.

String-based generation. The rule metadata is validated upstream via
:class:`mcp_sentinel_detection_engine.validation.TerraformRuleMetadata`, so by
the time we reach this module every field has already been Pydantic-checked.
HCL string interpolation is escape-only — no user-supplied identifier is
interpolated unquoted.
"""

from __future__ import annotations

import hashlib
import uuid

from .validation import TerraformRuleMetadata

_NAMESPACE = uuid.UUID("8c2c5e9b-7a13-4f51-b5e3-7b9c2a4d6f10")


def _escape_hcl_string(value: str) -> str:
    """Escape a string for safe embedding inside a double-quoted HCL literal."""
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace("${", "$${")
        .replace("%{", "%%{")
    )


def _stable_rule_uuid(name: str) -> str:
    digest = hashlib.sha256(name.encode("utf-8")).digest()
    return str(uuid.uuid5(_NAMESPACE, digest.hex()))


def _format_string_list(items: list[str]) -> str:
    if not items:
        return "[]"
    parts = ", ".join(f'"{_escape_hcl_string(item)}"' for item in items)
    return f"[{parts}]"


def _format_heredoc(query: str) -> str:
    marker = "EOT"
    while marker in query:
        marker += "X"
    lines = query.split("\n")
    body = "\n".join("    " + line if line else "" for line in lines)
    return f"<<-{marker}\n{body}\n  {marker}"


def emit_terraform(query: str, metadata: TerraformRuleMetadata) -> str:
    """Emit a single ``azurerm_sentinel_alert_rule_scheduled`` Terraform block.

    The caller is responsible for providing ``log_analytics_workspace_id`` at
    apply time via a Terraform variable; the emitted HCL references
    ``var.log_analytics_workspace_id``.
    """
    name_safe = metadata.name
    display = _escape_hcl_string(metadata.display_name)
    description = _escape_hcl_string(metadata.description)
    rule_uuid = _stable_rule_uuid(metadata.name)
    query_block = _format_heredoc(query)
    tactics = _format_string_list(metadata.tactics)
    techniques = _format_string_list(metadata.techniques)

    lines = [
        f'resource "azurerm_sentinel_alert_rule_scheduled" "{name_safe}" {{',
        "  log_analytics_workspace_id = var.log_analytics_workspace_id",
        f'  name                       = "{rule_uuid}"',
        f'  display_name               = "{display}"',
        f'  description                = "{description}"',
        f'  severity                   = "{metadata.severity.value}"',
        f"  enabled                    = {str(metadata.enabled).lower()}",
        f'  query_frequency            = "{metadata.query_frequency}"',
        f'  query_period               = "{metadata.query_period}"',
        f'  trigger_operator           = "{metadata.trigger_operator}"',
        f"  trigger_threshold          = {metadata.trigger_threshold}",
        f"  suppression_enabled        = {str(metadata.suppression_enabled).lower()}",
        f'  suppression_duration       = "{metadata.suppression_duration}"',
        f"  tactics                    = {tactics}",
        f"  techniques                 = {techniques}",
        f"  query                      = {query_block}",
        "}",
        "",
    ]
    return "\n".join(lines)
