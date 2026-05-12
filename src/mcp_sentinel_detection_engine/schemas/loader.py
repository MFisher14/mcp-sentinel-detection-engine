"""Load and query the bundled Sentinel table-schema snapshot."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from typing import Any


@lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    """Return the parsed ``sentinel_tables.json`` snapshot."""
    resource = files(__package__).joinpath("sentinel_tables.json")
    with resource.open("r", encoding="utf-8") as handle:
        data: Any = json.load(handle)
    if not isinstance(data, dict):
        raise RuntimeError("Bundled schema snapshot is malformed (root must be an object)")
    return data


def list_tables() -> list[str]:
    return sorted(load_schema().get("tables", {}).keys())


def get_table_columns(table: str) -> dict[str, str] | None:
    """Return ``{column_name: kusto_type}`` for ``table``, or ``None`` if unknown."""
    tables = load_schema().get("tables", {})
    entry = tables.get(table)
    if not isinstance(entry, dict):
        return None
    columns = entry.get("columns")
    if not isinstance(columns, dict):
        return None
    return {str(k): str(v) for k, v in columns.items()}
