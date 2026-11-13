"""``detect_rule_drift`` tool implementation."""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field, field_validator

from ..audit import audit_tool_call
from ..drift import compare
from ..errors import InvalidInputError, NotFoundError
from ..hcl_parse import MAX_HCL_LENGTH, ParsedRule, parse_rules
from ..management_client import ManagementClient
from ..tool_context import ToolContext
from ..validation import GUID_PATTERN, _TenantField, parse_input
from ._runtime import dispatch, resolve_targets

TOOL_NAME = "detect_rule_drift"
TOOL_DESCRIPTION = (
    "Detect drift between a checked-in ``azurerm_sentinel_alert_rule_scheduled`` "
    "HCL block (as emitted by ``generate_sentinel_terraform``) and the rule "
    "actually deployed in Sentinel. Reads the live rule read-only from the "
    "Azure Resource Manager ``Microsoft.SecurityInsights/alertRules`` API and "
    "returns a structured diff: ``added`` (set live, not declared), "
    "``removed`` (declared, missing live) and ``changed`` (``before`` = HCL, "
    "``after`` = live). Drift on ``enabled`` / ``query`` / ``severity`` / "
    "``tactics`` / ``techniques`` is listed in ``high_priority``. Identify the "
    "live rule by ``rule_id`` (GUID), by ``rule_name_pattern`` (glob over "
    "display name / name; must match exactly one rule), or omit both to use "
    "the GUID in the HCL ``name`` attribute. Provide the HCL inline (``hcl``) "
    "or as an absolute ``hcl_path``. Requires the tenant's management-plane "
    'config (subscription_id / resource_group / workspace_name). ``tenant: "*"`` '
    "checks the same rule across every tenant."
)

INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "rule_id": {
            "type": "string",
            "description": "Sentinel alert-rule GUID (the ARM resource ``name``).",
            "pattern": GUID_PATTERN.pattern,
        },
        "rule_name_pattern": {
            "type": "string",
            "description": (
                "Case-insensitive glob (``*``, ``?``) over the live rule's display "
                "name or GUID. Must match exactly one rule."
            ),
            "minLength": 1,
            "maxLength": 256,
        },
        "hcl": {
            "type": "string",
            "description": "Checked-in HCL. Mutually exclusive with ``hcl_path``.",
            "minLength": 1,
            "maxLength": MAX_HCL_LENGTH,
        },
        "hcl_path": {
            "type": "string",
            "description": "Absolute path to a .tf file. Mutually exclusive with ``hcl``.",
            "minLength": 1,
            "maxLength": 4096,
        },
        "resource_name": {
            "type": "string",
            "description": (
                "Terraform resource name to compare when the HCL contains several "
                "rule blocks. Defaults to the only block, or the block whose "
                "``name`` / ``display_name`` matches the live rule."
            ),
            "minLength": 1,
            "maxLength": 256,
        },
        "tenant": {
            "type": "string",
            "description": (
                "Tenant key to query. Omit for the configured default tenant. "
                "Use '*' to fan out across every configured tenant."
            ),
            "pattern": r"^([A-Za-z0-9_-]{1,64}|\*)$",
        },
    },
    "additionalProperties": False,
}


class DetectDriftInput(_TenantField):
    rule_id: str | None = None
    rule_name_pattern: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    hcl: Annotated[str, Field(min_length=1, max_length=MAX_HCL_LENGTH)] | None = None
    hcl_path: Annotated[str, Field(min_length=1, max_length=4096)] | None = None
    resource_name: Annotated[str, Field(min_length=1, max_length=256)] | None = None

    @field_validator("rule_id")
    @classmethod
    def _validate_rule_id(cls, value: str | None) -> str | None:
        if value is not None and not GUID_PATTERN.match(value):
            raise ValueError("rule_id must be a GUID")
        return value

    @field_validator("hcl_path")
    @classmethod
    def _validate_path(cls, value: str | None) -> str | None:
        if value is not None and "\x00" in value:
            raise ValueError("hcl_path must not contain NUL bytes")
        return value

    def model_post_init(self, __context: object) -> None:
        if (self.hcl is None) == (self.hcl_path is None):
            raise ValueError("provide exactly one of hcl or hcl_path")
        if self.rule_id is not None and self.rule_name_pattern is not None:
            raise ValueError("provide at most one of rule_id or rule_name_pattern")


def _read_hcl_path(path_str: str) -> str:
    path = Path(path_str)
    if not path.is_absolute():
        raise InvalidInputError("hcl_path must be an absolute path")
    if not path.is_file():
        raise InvalidInputError("hcl_path does not point to a file")
    try:
        data = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InvalidInputError(f"hcl_path could not be read: {exc.strerror}") from exc
    if len(data) > MAX_HCL_LENGTH:
        raise InvalidInputError(f"hcl_path file exceeds {MAX_HCL_LENGTH} characters")
    return data


def _properties(resource: dict[str, Any]) -> dict[str, Any]:
    props = resource.get("properties")
    return props if isinstance(props, dict) else {}


def _select_block(
    blocks: list[ParsedRule], resource_name: str | None, live: dict[str, Any] | None
) -> ParsedRule:
    if resource_name is not None:
        for block in blocks:
            if block.resource_name == resource_name:
                return block
        raise InvalidInputError("resource_name not found in the supplied HCL")
    if len(blocks) == 1:
        return blocks[0]
    if live is not None:
        props = _properties(live)
        for block in blocks:
            if block.attributes.get("name") == live.get("name") or (
                block.attributes.get("display_name") == props.get("displayName")
            ):
                return block
    raise InvalidInputError("HCL contains several rule blocks; pass resource_name to choose one")


async def _resolve_by_pattern(client: ManagementClient, pattern: str) -> dict[str, Any]:
    lowered = pattern.lower()
    matches = []
    for rule in await client.list_alert_rules():
        props = _properties(rule)
        candidates = [rule.get("name"), props.get("displayName")]
        if any(isinstance(c, str) and fnmatch.fnmatchcase(c.lower(), lowered) for c in candidates):
            matches.append(rule)
    if not matches:
        raise NotFoundError("No deployed rule matches rule_name_pattern")
    if len(matches) > 1:
        raise InvalidInputError(
            f"rule_name_pattern matched {len(matches)} rules; narrow it or pass rule_id"
        )
    return matches[0]


async def run(ctx: ToolContext, raw_params: dict[str, Any]) -> dict[str, Any]:
    params = parse_input(DetectDriftInput, raw_params)
    hcl = params.hcl if params.hcl is not None else _read_hcl_path(params.hcl_path or "")
    blocks = parse_rules(hcl)
    targets = resolve_targets(ctx, params.tenant)

    if params.rule_id is None and params.rule_name_pattern is None:
        default_block = _select_block(blocks, params.resource_name, None)
        declared_guid = default_block.attributes.get("name")
        if not isinstance(declared_guid, str) or not GUID_PATTERN.match(declared_guid):
            raise InvalidInputError(
                "HCL block has no GUID `name`; pass rule_id or rule_name_pattern"
            )
        rule_id: str | None = declared_guid
    else:
        rule_id = params.rule_id

    audit_params = {
        "rule_id": rule_id,
        "rule_name_pattern": params.rule_name_pattern,
        "hcl_source": "inline" if params.hcl is not None else "path",
        "hcl_block_count": len(blocks),
        "tenants": targets,
    }

    async def _call(client: ManagementClient) -> dict[str, Any]:
        if rule_id is not None:
            live = await client.get_alert_rule(rule_id)
        else:
            live = await _resolve_by_pattern(client, params.rule_name_pattern or "")
        declared = _select_block(blocks, params.resource_name, live)
        props = _properties(live)
        report = compare(declared, props)
        warnings: list[str] = []
        if live.get("kind") not in (None, "Scheduled"):
            warnings.append(
                f"Live rule kind is {live.get('kind')!r}; HCL describes a Scheduled rule."
            )
        declared_guid = declared.attributes.get("name")
        if isinstance(declared_guid, str) and declared_guid != live.get("name"):
            warnings.append("HCL `name` GUID differs from the live rule's GUID.")
        return {
            "drifted": report.drifted,
            "rule_id": live.get("name"),
            "display_name": props.get("displayName"),
            "resource_name": declared.resource_name,
            "high_priority": report.high_priority,
            "changed": report.changed,
            "added": report.added,
            "removed": report.removed,
            "warnings": warnings,
        }

    with audit_tool_call(TOOL_NAME, audit_params) as audit_extra:
        result = await dispatch(
            ctx, TOOL_NAME, targets, _call, client_factory=ctx.management_client_for
        )
        audit_extra["tenant_count"] = len(targets)
        if len(targets) == 1:
            audit_extra["drifted"] = result["drifted"]
            audit_extra["high_priority"] = result["high_priority"]
        return result
