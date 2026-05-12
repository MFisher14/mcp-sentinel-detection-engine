"""``generate_sentinel_terraform`` tool implementation."""

from __future__ import annotations

from typing import Any

from ..audit import audit_tool_call
from ..terraform_emit import emit_terraform
from ..tool_context import ToolContext
from ..validation import EmitTerraformInput, parse_input

TOOL_NAME = "generate_sentinel_terraform"
TOOL_DESCRIPTION = (
    "Emit a Terraform ``azurerm_sentinel_alert_rule_scheduled`` HCL block from "
    "a validated KQL query and rule metadata (name, severity, MITRE ATT&CK "
    "tactics/techniques, query frequency, query period, trigger threshold). "
    "Pure function — no Azure auth or network call. The emitted HCL references "
    "``var.log_analytics_workspace_id`` so the same module can be applied to "
    "any workspace. Resource GUIDs are derived server-side from a stable "
    "namespace UUID hashed against the rule name; user input is never "
    "interpolated unquoted. Returns the HCL string and the generated rule "
    "GUID. The ``tenant`` parameter is accepted for symmetry but is unused "
    "by this tool (emission is workspace-agnostic)."
)

INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "query": {
            "type": "string",
            "description": "The KQL query body to deploy. Max 10,000 chars.",
            "minLength": 1,
            "maxLength": 10_000,
        },
        "metadata": {
            "type": "object",
            "description": (
                "Rule metadata. ``name`` must be a Terraform-safe identifier. "
                "``severity`` ∈ {High, Medium, Low, Informational}. "
                "``query_frequency``/``query_period``/``suppression_duration`` "
                "are ISO 8601 durations. ``tactics`` are MITRE ATT&CK tactic "
                "names (e.g. ``InitialAccess``); ``techniques`` are technique "
                "IDs (e.g. ``T1059`` or ``T1059.001``)."
            ),
            "properties": {
                "name": {"type": "string", "minLength": 1, "maxLength": 256},
                "display_name": {"type": "string", "minLength": 1, "maxLength": 256},
                "description": {"type": "string", "maxLength": 4000},
                "severity": {
                    "type": "string",
                    "enum": ["High", "Medium", "Low", "Informational"],
                },
                "enabled": {"type": "boolean"},
                "query_frequency": {"type": "string"},
                "query_period": {"type": "string"},
                "trigger_operator": {
                    "type": "string",
                    "enum": ["GreaterThan", "LessThan", "Equal", "NotEqual"],
                },
                "trigger_threshold": {"type": "integer", "minimum": 0, "maximum": 10_000},
                "suppression_enabled": {"type": "boolean"},
                "suppression_duration": {"type": "string"},
                "tactics": {"type": "array", "items": {"type": "string"}, "maxItems": 32},
                "techniques": {"type": "array", "items": {"type": "string"}, "maxItems": 64},
            },
            "required": ["name", "display_name"],
            "additionalProperties": False,
        },
        "tenant": {
            "type": "string",
            "description": "Accepted for symmetry; unused by this tool.",
            "pattern": r"^([A-Za-z0-9_-]{1,64}|\*)$",
        },
    },
    "required": ["query", "metadata"],
    "additionalProperties": False,
}


async def run(ctx: ToolContext, raw_params: dict[str, Any]) -> dict[str, Any]:
    del ctx  # this tool is workspace-agnostic
    params = parse_input(EmitTerraformInput, raw_params)
    audit_params = {
        "rule_name": params.metadata.name,
        "severity": params.metadata.severity.value,
        "query_length": len(params.query),
        "tactic_count": len(params.metadata.tactics),
        "technique_count": len(params.metadata.techniques),
    }
    with audit_tool_call(TOOL_NAME, audit_params) as audit_extra:
        hcl = emit_terraform(params.query, params.metadata)
        audit_extra["hcl_length"] = len(hcl)
        return {
            "terraform_hcl": hcl,
            "metadata": {
                "rule_name": params.metadata.name,
                "severity": params.metadata.severity.value,
                "tactics": list(params.metadata.tactics),
                "techniques": list(params.metadata.techniques),
            },
        }
