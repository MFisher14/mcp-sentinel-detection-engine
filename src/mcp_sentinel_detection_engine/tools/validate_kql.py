"""``validate_kql_against_schema`` tool implementation."""

from __future__ import annotations

import difflib
import re
from typing import Any

from ..audit import audit_tool_call
from ..errors import SchemaValidationError
from ..schemas.loader import get_table_columns, list_tables
from ..tool_context import ToolContext
from ..validation import MAX_KQL_LENGTH, ValidateKqlInput, parse_input

TOOL_NAME = "validate_kql_against_schema"
TOOL_DESCRIPTION = (
    "Statically validate a KQL query against the bundled Log Analytics / "
    "Sentinel schema snapshot. Returns ``valid`` (bool), the list of "
    "``unknown_columns`` referenced by the query that don't appear in the "
    "target table's schema, and ``suggestions`` (closest-match column names "
    "via difflib). No live Azure API call is made — this is a fast offline "
    "check the model can run before paying the round-trip of ``dry_run_kql``. "
    "v0.2 will fetch the workspace schema live via the Log Analytics metadata "
    "API. The ``tenant`` parameter is accepted for symmetry but is unused."
)

INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "query": {
            "type": "string",
            "description": "KQL query to validate. Max 10,000 chars.",
            "minLength": 1,
            "maxLength": MAX_KQL_LENGTH,
        },
        "table": {
            "type": "string",
            "description": (
                "Target Log Analytics table name (e.g. ``SecurityEvent``, ``SigninLogs``)."
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
    "required": ["query", "table"],
    "additionalProperties": False,
}

_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_KQL_RESERVED = frozenset(
    {
        "and",
        "or",
        "not",
        "in",
        "has",
        "has_any",
        "has_all",
        "contains",
        "startswith",
        "endswith",
        "matches",
        "regex",
        "between",
        "where",
        "extend",
        "project",
        "summarize",
        "join",
        "union",
        "let",
        "datatable",
        "print",
        "top",
        "take",
        "sort",
        "order",
        "by",
        "on",
        "asc",
        "desc",
        "true",
        "false",
        "null",
        "dynamic",
        "string",
        "int",
        "long",
        "real",
        "datetime",
        "timespan",
        "bool",
        "guid",
        "ago",
        "now",
        "count",
        "dcount",
        "sum",
        "avg",
        "min",
        "max",
        "tostring",
        "tolower",
        "toupper",
        "bin",
        "iff",
        "case",
        "parse",
        "split",
        "strcat",
        "make_list",
        "make_set",
        "arg_max",
        "arg_min",
    }
)


def _extract_referenced_columns(query: str, known_tables: set[str]) -> list[str]:
    """Best-effort regex extraction of identifiers that look like column references.

    This is intentionally an over-approximation: anything that looks like a bare
    identifier and isn't a KQL keyword or a known table name gets returned. The
    output is deduplicated and stable-ordered.
    """
    found: list[str] = []
    seen: set[str] = set()
    for match in _IDENTIFIER_RE.finditer(query):
        ident = match.group(0)
        if ident in seen:
            continue
        lowered = ident.lower()
        if lowered in _KQL_RESERVED:
            continue
        if ident in known_tables:
            continue
        if ident.isdigit():
            continue
        seen.add(ident)
        found.append(ident)
    return found


async def run(ctx: ToolContext, raw_params: dict[str, Any]) -> dict[str, Any]:
    del ctx
    params = parse_input(ValidateKqlInput, raw_params)
    columns = get_table_columns(params.table)
    audit_params = {
        "table": params.table,
        "query_length": len(params.query),
    }
    with audit_tool_call(TOOL_NAME, audit_params) as audit_extra:
        if columns is None:
            raise SchemaValidationError(
                f"Table '{params.table}' is not in the bundled schema snapshot. "
                f"Known tables: {', '.join(list_tables())}."
            )
        column_names = set(columns.keys())
        known_tables = set(list_tables())
        referenced = _extract_referenced_columns(params.query, known_tables)
        unknown = [name for name in referenced if name not in column_names]
        suggestions: dict[str, list[str]] = {}
        for name in unknown:
            close = difflib.get_close_matches(name, column_names, n=3, cutoff=0.6)
            if close:
                suggestions[name] = close
        valid = len(unknown) == 0
        audit_extra["unknown_count"] = len(unknown)
        audit_extra["valid"] = valid
        return {
            "valid": valid,
            "table": params.table,
            "unknown_columns": unknown,
            "suggestions": suggestions,
            "metadata": {
                "schema_column_count": len(column_names),
                "referenced_column_count": len(referenced),
            },
        }
