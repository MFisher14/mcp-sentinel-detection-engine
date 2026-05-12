"""Sigma → KQL conversion via pySigma with the Kusto backend.

Uses :func:`sigma.pipelines.azuremonitor.azure_monitor_pipeline` to target the
Azure Log Analytics / Microsoft Sentinel table set (``SecurityEvent``,
``SigninLogs``, ``AuditLogs``, ``OfficeActivity``, ``CommonSecurityLog``,
``Syslog`` and friends).

Backend choice — ``pysigma-backend-kusto`` over
``pysigma-backend-microsoft365defender``:

- Sentinel's data plane is Log Analytics KQL with tables like ``SecurityEvent``
  and ``SigninLogs`` — exactly what the Kusto backend's ``azure_monitor``
  pipeline produces.
- The Defender XDR backend targets the Advanced Hunting table set
  (``DeviceProcessEvents`` and siblings); those tables only exist inside the
  Defender ``securitycenter.microsoft.com`` endpoint, not in a standard Log
  Analytics workspace.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sigma.backends.kusto import KustoBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.pipelines.azuremonitor import azure_monitor_pipeline

from .errors import ConversionError

_TABLE_HEAD_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)")


@dataclass(frozen=True)
class ConversionResult:
    """One Sigma rule may expand into multiple KQL queries; this carries one of them."""

    kql: str
    target_table: str | None
    warnings: list[str]


def convert_sigma(sigma_yaml: str, *, target_table: str | None = None) -> list[ConversionResult]:
    """Convert one or more Sigma rules in a YAML string to KQL queries.

    The ``azure_monitor`` pipeline auto-detects the target table for Windows
    rules whose logsource implies an EventID-based (``service: security``) or
    category-based (``process_creation``, ``file_event``, ...) mapping. For
    rules whose logsource does not have a built-in mapping —
    ``signinlogs``, ``auditlogs``, ``officeactivity``, ``azureactivity`` and
    friends — the caller must pass ``target_table`` explicitly.

    Raises ``ConversionError`` on any backend failure. Warnings from pySigma
    pipeline post-processing are surfaced on each :class:`ConversionResult`.
    """
    try:
        collection = SigmaCollection.from_yaml(sigma_yaml)
    except SigmaError as exc:
        raise ConversionError(f"Failed to parse Sigma YAML: {exc}") from exc
    except Exception as exc:
        raise ConversionError(f"Failed to parse Sigma YAML: {exc}") from exc

    if not collection.rules:
        raise ConversionError("Sigma YAML did not contain any rules")

    pipeline_kwargs: dict[str, Any] = {}
    if target_table is not None:
        pipeline_kwargs["query_table"] = target_table

    try:
        backend = KustoBackend(processing_pipeline=azure_monitor_pipeline(**pipeline_kwargs))
        queries: Any = backend.convert(collection)
    except SigmaError as exc:
        raise ConversionError(f"Sigma → KQL conversion failed: {exc}") from exc

    if not isinstance(queries, list) or not queries:
        raise ConversionError("Sigma → KQL conversion produced no output")

    backend_warnings = _collect_backend_warnings(backend)

    results: list[ConversionResult] = []
    for raw in queries:
        text = str(raw).strip()
        if not text:
            continue
        results.append(
            ConversionResult(
                kql=text,
                target_table=_extract_target_table(text),
                warnings=list(backend_warnings),
            )
        )

    if not results:
        raise ConversionError("Sigma → KQL conversion produced no non-empty queries")

    return results


def _extract_target_table(kql: str) -> str | None:
    match = _TABLE_HEAD_RE.match(kql)
    if match is None:
        return None
    candidate = match.group(1)
    # KQL queries that start with `let` or `print` aren't a single-table query.
    if candidate.lower() in {"let", "print", "search", "union"}:
        return None
    return candidate


def _collect_backend_warnings(backend: KustoBackend) -> list[str]:
    warnings: list[str] = []
    errors_attr = getattr(backend, "errors", None)
    if isinstance(errors_attr, list):
        for item in errors_attr:
            warnings.append(str(item))
    pipeline = getattr(backend, "processing_pipeline", None)
    pipeline_errors = getattr(pipeline, "errors", None)
    if isinstance(pipeline_errors, list):
        for item in pipeline_errors:
            warnings.append(str(item))
    return warnings
