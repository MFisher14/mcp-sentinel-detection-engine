"""``convert_sigma_to_kql`` tool implementation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..audit import audit_tool_call
from ..errors import InvalidInputError
from ..sigma_pipeline import convert_sigma
from ..tool_context import ToolContext
from ..validation import MAX_SIGMA_LENGTH, ConvertSigmaInput, parse_input

TOOL_NAME = "convert_sigma_to_kql"
TOOL_DESCRIPTION = (
    "Convert a Sigma rule (YAML string or filesystem path) into Microsoft "
    "Sentinel KQL using pySigma's Kusto backend with the ``azure_monitor`` "
    "pipeline. Returns the generated KQL, the inferred target Log Analytics "
    "table(s) (``SecurityEvent``, ``SigninLogs``, etc.), and any pySigma "
    "conversion warnings. Pure function — no Azure authentication or network "
    "call is required. The pipeline auto-detects the table for Windows "
    "logsources (``service: security``, ``category: process_creation`` and "
    "siblings); for rules whose logsource is not a built-in Windows mapping "
    "(``signinlogs``, ``auditlogs``, ``officeactivity``, ``azureactivity``, "
    "``commonsecuritylog``, ``syslog``) pass ``target_table`` explicitly. "
    "Treat the returned KQL as a starting point; always follow with "
    "``validate_kql_against_schema`` and ``dry_run_kql`` before deploying via "
    "``generate_sentinel_terraform``. The ``tenant`` parameter is accepted "
    "for symmetry but is unused by this tool."
)

INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "sigma_yaml": {
            "type": "string",
            "description": (
                "The full Sigma rule (or multi-document collection) as a YAML "
                "string. Mutually exclusive with ``sigma_path``."
            ),
            "minLength": 1,
            "maxLength": MAX_SIGMA_LENGTH,
        },
        "sigma_path": {
            "type": "string",
            "description": (
                "Absolute filesystem path to a Sigma rule YAML file. Mutually "
                "exclusive with ``sigma_yaml``."
            ),
            "minLength": 1,
            "maxLength": 4096,
        },
        "target_table": {
            "type": "string",
            "description": (
                "Explicit Log Analytics table to target. Required when the "
                "Sigma rule's logsource has no built-in azure_monitor mapping "
                "(e.g. ``signinlogs``, ``auditlogs``)."
            ),
            "minLength": 1,
            "maxLength": 128,
        },
        "tenant": {
            "type": "string",
            "description": "Accepted for symmetry; unused by this tool.",
            "pattern": r"^([A-Za-z0-9_-]{1,64}|\*)$",
        },
    },
    "additionalProperties": False,
}


def _read_sigma_path(path_str: str) -> str:
    path = Path(path_str)
    if not path.is_absolute():
        raise InvalidInputError("sigma_path must be an absolute path")
    if not path.is_file():
        raise InvalidInputError("sigma_path does not point to a file")
    try:
        data = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InvalidInputError(f"sigma_path could not be read: {exc.strerror}") from exc
    if len(data) > MAX_SIGMA_LENGTH:
        raise InvalidInputError(f"sigma_path file exceeds {MAX_SIGMA_LENGTH} characters")
    return data


async def run(ctx: ToolContext, raw_params: dict[str, Any]) -> dict[str, Any]:
    del ctx
    params = parse_input(ConvertSigmaInput, raw_params)
    sigma_yaml = params.sigma_yaml
    source: str
    if sigma_yaml is None:
        # validation.ConvertSigmaInput guarantees exactly one of yaml/path is set.
        sigma_path = params.sigma_path or ""
        sigma_yaml = _read_sigma_path(sigma_path)
        source = "path"
    else:
        source = "inline"

    audit_params = {
        "source": source,
        "yaml_length": len(sigma_yaml),
        "target_table": params.target_table,
    }
    with audit_tool_call(TOOL_NAME, audit_params) as audit_extra:
        results = convert_sigma(sigma_yaml, target_table=params.target_table)
        audit_extra["query_count"] = len(results)
        return {
            "queries": [
                {
                    "kql": item.kql,
                    "target_table": item.target_table,
                    "warnings": item.warnings,
                }
                for item in results
            ],
            "metadata": {
                "query_count": len(results),
                "target_tables": sorted(
                    {item.target_table for item in results if item.target_table is not None}
                ),
            },
        }
