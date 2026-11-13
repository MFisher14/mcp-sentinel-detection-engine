"""``link_hunt_to_rule`` tool implementation."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field, field_validator

from ..audit import audit_tool_call
from ..hunt_link import link_hunt
from ..tool_context import ToolContext
from ..validation import (
    MAX_KQL_LENGTH,
    _strip_control_chars,
    _TenantField,
    _validate_kql_payload,
    parse_input,
)

TOOL_NAME = "link_hunt_to_rule"
TOOL_DESCRIPTION = (
    "Bridge a Defender XDR Advanced Hunting query (e.g. one just run via the "
    "companion ``mcp-defender-xdr`` server) into this server's detection "
    "pipeline. Returns (1) the query re-targeted at the Sentinel / Log "
    "Analytics schema — best-effort table mapping (``AADSignInEventsBeta`` → "
    "``SigninLogs`` with column renames, ``Device*`` / ``Email*`` / "
    "``Identity*`` tables kept as-is with a note that they require the "
    "Defender XDR connector's raw-event streaming) and ``Timestamp`` → "
    "``TimeGenerated``; (2) a Sigma rule skeleton seeded from the query's "
    'simple ``field == "value"`` / ``has`` / ``in (...)`` predicates; and '
    "(3) mapping notes and warnings. Pure function — no Azure auth or network "
    "call. Follow with ``convert_sigma_to_kql`` on the skeleton and "
    "``validate_kql_against_schema`` on the re-targeted query. Only the "
    "Defender → Sentinel direction is supported."
)

INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "query": {
            "type": "string",
            "description": "Defender XDR Advanced Hunting KQL. Max 10,000 chars.",
            "minLength": 1,
            "maxLength": MAX_KQL_LENGTH,
        },
        "title": {
            "type": "string",
            "description": "Title for the generated Sigma skeleton.",
            "minLength": 1,
            "maxLength": 256,
        },
        "tenant": {
            "type": "string",
            "description": "Accepted for symmetry; unused by this tool.",
            "pattern": r"^([A-Za-z0-9_-]{1,64}|\*)$",
        },
    },
    "required": ["query"],
    "additionalProperties": False,
}


class LinkHuntInput(_TenantField):
    query: Annotated[str, Field(min_length=1, max_length=MAX_KQL_LENGTH)]
    title: Annotated[str, Field(min_length=1, max_length=256)] = (
        "Hunt-derived detection (review before use)"
    )

    @field_validator("query")
    @classmethod
    def _validate_query(cls, value: str) -> str:
        return _validate_kql_payload(value)

    @field_validator("title")
    @classmethod
    def _validate_title(cls, value: str) -> str:
        cleaned = " ".join(_strip_control_chars(value).split())
        if not cleaned:
            raise ValueError("title must contain non-whitespace characters")
        return cleaned


async def run(ctx: ToolContext, raw_params: dict[str, Any]) -> dict[str, Any]:
    del ctx
    params = parse_input(LinkHuntInput, raw_params)
    with audit_tool_call(TOOL_NAME, {"query_length": len(params.query)}) as audit_extra:
        result = link_hunt(params.query, title=params.title)
        audit_extra["source_tables"] = result.source_tables
        audit_extra["target_tables"] = result.target_tables
        return {
            "sentinel_query": result.sentinel_query,
            "source_tables": result.source_tables,
            "target_tables": result.target_tables,
            "table_mappings": result.table_mappings,
            "column_mappings": result.column_mappings,
            "sigma_skeleton": result.sigma_skeleton,
            "warnings": result.warnings,
        }
