"""Field-by-field drift comparison between checked-in HCL and a live Sentinel rule."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .hcl_parse import ParsedRule

# HCL attribute -> ARM ``properties`` key.
FIELD_MAP: dict[str, str] = {
    "display_name": "displayName",
    "description": "description",
    "severity": "severity",
    "enabled": "enabled",
    "query": "query",
    "query_frequency": "queryFrequency",
    "query_period": "queryPeriod",
    "trigger_operator": "triggerOperator",
    "trigger_threshold": "triggerThreshold",
    "suppression_enabled": "suppressionEnabled",
    "suppression_duration": "suppressionDuration",
    "tactics": "tactics",
    "techniques": "techniques",
}
HIGH_PRIORITY_FIELDS = frozenset({"enabled", "query", "severity", "tactics", "techniques"})
_DURATION_FIELDS = frozenset({"query_frequency", "query_period", "suppression_duration"})
_LIST_FIELDS = frozenset({"tactics", "techniques"})

_DURATION_RE = re.compile(
    r"^P(?:(?P<w>\d+)W)?(?:(?P<d>\d+)D)?(?:T(?:(?P<h>\d+)H)?(?:(?P<m>\d+)M)?(?:(?P<s>\d+)S)?)?$"
)


def duration_seconds(value: str) -> int | None:
    """Parse the ISO-8601 durations Sentinel uses (no years/months)."""
    match = _DURATION_RE.match(value)
    if match is None or value in {"P", "PT"}:
        return None
    parts = {k: int(v) if v else 0 for k, v in match.groupdict().items()}
    return (
        parts["w"] * 604_800
        + parts["d"] * 86_400
        + parts["h"] * 3_600
        + parts["m"] * 60
        + parts["s"]
    )


def _normalize_query(value: str) -> str:
    lines = value.replace("\r\n", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines).strip()


def _normalize(field: str, value: Any) -> Any:
    if value is None:
        return None
    if field in _LIST_FIELDS and isinstance(value, list):
        return sorted(str(v) for v in value)
    if field in _DURATION_FIELDS and isinstance(value, str):
        seconds = duration_seconds(value)
        return seconds if seconds is not None else value
    if field == "query" and isinstance(value, str):
        return _normalize_query(value)
    return value


def _is_empty(field: str, value: Any) -> bool:
    if value is None:
        return True
    if field in _LIST_FIELDS and value == []:
        return True
    return field == "description" and value == ""


@dataclass
class DriftReport:
    added: list[dict[str, Any]]
    removed: list[dict[str, Any]]
    changed: list[dict[str, Any]]
    high_priority: list[str]

    @property
    def drifted(self) -> bool:
        return bool(self.added or self.removed or self.changed)


def compare(declared: ParsedRule, live_properties: dict[str, Any]) -> DriftReport:
    """Compare declared HCL attributes to live ARM ``properties``.

    - ``changed``: set on both sides with different (normalized) values.
    - ``added``: set on the live rule but not declared in the HCL.
    - ``removed``: declared in the HCL but absent on the live rule.

    ``before`` is always the checked-in (HCL) value, ``after`` the live value.
    """
    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    for hcl_key, arm_key in FIELD_MAP.items():
        before = declared.attributes.get(hcl_key)
        after = live_properties.get(arm_key)
        before_empty = _is_empty(hcl_key, before)
        after_empty = _is_empty(hcl_key, after)
        if before_empty and after_empty:
            continue
        entry: dict[str, Any] = {"field": hcl_key, "high_priority": hcl_key in HIGH_PRIORITY_FIELDS}
        if before_empty:
            added.append(entry | {"value": after})
        elif after_empty:
            removed.append(entry | {"value": before})
        elif _normalize(hcl_key, before) != _normalize(hcl_key, after):
            changed.append(entry | {"before": before, "after": after})
    high_priority = sorted({e["field"] for e in (*added, *removed, *changed) if e["high_priority"]})
    return DriftReport(added=added, removed=removed, changed=changed, high_priority=high_priority)
