"""Defender XDR Advanced Hunting KQL → Sentinel KQL + Sigma skeleton (best effort).

Pure functions, no network. This is the hand-off point between
``mcp-defender-xdr`` (hunt) and this server (ship a rule): Claude runs a hunt
in Defender XDR, then passes the query here to get a Sentinel-targeted query
and a Sigma rule to iterate on. The two servers never talk to each other
directly; the orchestration happens in the MCP client.

Only the Defender → Sentinel direction is implemented. Sentinel → Defender is
asymmetric (Defender's schema is a narrower, device/identity/email-centric
subset) and is intentionally out of scope.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True)
class TableMapping:
    target: str
    note: str
    columns: dict[str, str] = field(default_factory=dict)


_MDE_NOTE = (
    "Available in Sentinel only when the Microsoft Defender XDR connector streams "
    "Defender for Endpoint raw events."
)
_MDO_NOTE = (
    "Available in Sentinel only when the Microsoft Defender XDR connector streams "
    "Defender for Office 365 raw events."
)
_MDI_NOTE = (
    "Available in Sentinel only when the Microsoft Defender XDR connector streams "
    "Defender for Identity raw events; on-prem logons are also in SecurityEvent."
)

TABLE_MAP: dict[str, TableMapping] = {
    **{
        t: TableMapping(t, _MDE_NOTE)
        for t in (
            "DeviceProcessEvents",
            "DeviceNetworkEvents",
            "DeviceFileEvents",
            "DeviceRegistryEvents",
            "DeviceLogonEvents",
            "DeviceImageLoadEvents",
            "DeviceEvents",
            "DeviceInfo",
            "DeviceNetworkInfo",
            "DeviceFileCertificateInfo",
        )
    },
    **{
        t: TableMapping(t, _MDO_NOTE)
        for t in (
            "EmailEvents",
            "EmailAttachmentInfo",
            "EmailUrlInfo",
            "EmailPostDeliveryEvents",
            "UrlClickEvents",
        )
    },
    **{
        t: TableMapping(t, _MDI_NOTE)
        for t in ("IdentityLogonEvents", "IdentityQueryEvents", "IdentityDirectoryEvents")
    },
    "CloudAppEvents": TableMapping(
        "CloudAppEvents",
        "Streamed by the Defender XDR connector (Defender for Cloud Apps); "
        "Office 365 audit data is also in OfficeActivity.",
    ),
    "AADSignInEventsBeta": TableMapping(
        "SigninLogs",
        "Entra ID interactive sign-ins live in SigninLogs in Sentinel; columns renamed.",
        {
            "AccountUpn": "UserPrincipalName",
            "AccountDisplayName": "UserDisplayName",
            "AccountObjectId": "UserId",
            "Application": "AppDisplayName",
            "ApplicationId": "AppId",
            "ErrorCode": "ResultType",
            "Country": "Location",
            "ClientAppUsed": "ClientAppUsed",
            "IPAddress": "IPAddress",
            "RiskLevelDuringSignIn": "RiskLevelDuringSignIn",
            "ConditionalAccessStatus": "ConditionalAccessStatus",
            "CorrelationId": "CorrelationId",
        },
    ),
    "AADSpnSignInEventsBeta": TableMapping(
        "AADServicePrincipalSignInLogs",
        "Service-principal sign-ins live in AADServicePrincipalSignInLogs; columns renamed.",
        {
            "ServicePrincipalName": "ServicePrincipalName",
            "ServicePrincipalId": "ServicePrincipalId",
            "Application": "AppDisplayName",
            "ApplicationId": "AppId",
            "ErrorCode": "ResultType",
            "IPAddress": "IPAddress",
        },
    ),
    "AlertInfo": TableMapping(
        "SecurityAlert",
        "Alert shape differs substantially (AlertName, Entities JSON); review by hand.",
        {"Title": "AlertName", "Severity": "AlertSeverity"},
    ),
    "AlertEvidence": TableMapping(
        "SecurityAlert",
        "Evidence is embedded in SecurityAlert.Entities as JSON; review by hand.",
    ),
}

GLOBAL_COLUMN_MAP = {"Timestamp": "TimeGenerated"}

# Sigma logsource + field-name hints per (source) table.
_PROCESS_FIELDS = {
    "FileName": "Image",
    "FolderPath": "Image",
    "ProcessCommandLine": "CommandLine",
    "InitiatingProcessFileName": "ParentImage",
    "InitiatingProcessCommandLine": "ParentCommandLine",
    "AccountName": "User",
    "SHA256": "Hashes",
}
_LOGSOURCES: dict[str, tuple[dict[str, str], dict[str, str]]] = {
    "DeviceProcessEvents": (
        {"product": "windows", "category": "process_creation"},
        _PROCESS_FIELDS,
    ),
    "DeviceNetworkEvents": (
        {"product": "windows", "category": "network_connection"},
        {
            "RemoteIP": "DestinationIp",
            "RemotePort": "DestinationPort",
            "RemoteUrl": "DestinationHostname",
            "InitiatingProcessFileName": "Image",
        },
    ),
    "DeviceFileEvents": (
        {"product": "windows", "category": "file_event"},
        {"FileName": "TargetFilename", "FolderPath": "TargetFilename"},
    ),
    "DeviceRegistryEvents": (
        {"product": "windows", "category": "registry_event"},
        {"RegistryKey": "TargetObject", "RegistryValueData": "Details"},
    ),
    "DeviceImageLoadEvents": (
        {"product": "windows", "category": "image_load"},
        {"FileName": "ImageLoaded", "FolderPath": "ImageLoaded"},
    ),
    "AADSignInEventsBeta": ({"product": "azure", "service": "signinlogs"}, {}),
    "SigninLogs": ({"product": "azure", "service": "signinlogs"}, {}),
    "AuditLogs": ({"product": "azure", "service": "auditlogs"}, {}),
}

_STRING_RE = re.compile(r"@?'(?:[^'\\]|\\.)*'|@?\"(?:[^\"\\]|\\.)*\"")
_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_PREDICATE_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(==|=~|has_cs|has|contains_cs|contains|startswith|endswith)\s*"
    r"(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')"
)
_IN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s+in~?\s*\(([^)]*)\)")
_OP_MODIFIER = {
    "==": "",
    "=~": "",
    "has": "|contains",
    "has_cs": "|contains",
    "contains": "|contains",
    "contains_cs": "|contains",
    "startswith": "|startswith",
    "endswith": "|endswith",
}


def _split_code_and_strings(query: str) -> list[tuple[bool, str]]:
    """Return ``[(is_string_literal, text), ...]`` covering ``query``."""
    parts: list[tuple[bool, str]] = []
    pos = 0
    for match in _STRING_RE.finditer(query):
        if match.start() > pos:
            parts.append((False, query[pos : match.start()]))
        parts.append((True, match.group(0)))
        pos = match.end()
    if pos < len(query):
        parts.append((False, query[pos:]))
    return parts


def _unquote(literal: str) -> str:
    body = literal.lstrip("@")[1:-1]
    if literal.startswith("@"):
        return body
    return re.sub(r"\\(.)", r"\1", body)


@dataclass
class HuntLinkResult:
    sentinel_query: str
    source_tables: list[str]
    target_tables: list[str]
    table_mappings: list[dict[str, str]]
    column_mappings: list[dict[str, str]]
    warnings: list[str]
    sigma_skeleton: str


def retarget_query(
    query: str,
) -> tuple[str, list[str], list[str], list[dict[str, str]], list[dict[str, str]], list[str]]:
    """Rewrite table and column identifiers outside string literals."""
    code = "".join(text for is_str, text in _split_code_and_strings(query) if not is_str)
    idents = set(_IDENT_RE.findall(code))
    source_tables = sorted(t for t in idents if t in TABLE_MAP)
    replacements: dict[str, str] = dict(GLOBAL_COLUMN_MAP)
    table_mappings: list[dict[str, str]] = []
    for table in source_tables:
        mapping = TABLE_MAP[table]
        table_mappings.append({"source": table, "target": mapping.target, "note": mapping.note})
        if mapping.target != table:
            replacements[table] = mapping.target
        for src_col, dst_col in mapping.columns.items():
            if src_col != dst_col:
                replacements.setdefault(src_col, dst_col)
    applied = sorted(k for k in replacements if k in idents and k not in TABLE_MAP)
    column_mappings = [{"source": k, "target": replacements[k]} for k in applied]

    def _rewrite(text: str) -> str:
        return _IDENT_RE.sub(lambda m: replacements.get(m.group(0), m.group(0)), text)

    rewritten = "".join(
        text if is_str else _rewrite(text) for is_str, text in _split_code_and_strings(query)
    )
    warnings: list[str] = []
    if not source_tables:
        warnings.append(
            "No known Defender XDR Advanced Hunting table found; query returned unchanged "
            "apart from column renames."
        )
    target_tables = sorted({TABLE_MAP[t].target for t in source_tables})
    return rewritten, source_tables, target_tables, table_mappings, column_mappings, warnings


def _yaml_str(value: str) -> str:
    # JSON strings are valid YAML double-quoted scalars and escape everything risky.
    return json.dumps(value, ensure_ascii=True)


def build_sigma_skeleton(
    query: str, source_tables: list[str], *, title: str, warnings: list[str]
) -> str:
    primary = source_tables[0] if source_tables else None
    logsource, field_map = _LOGSOURCES.get(
        primary or "", ({"product": "m365_defender", "service": (primary or "unknown").lower()}, {})
    )
    if primary is not None and primary not in _LOGSOURCES:
        warnings.append(
            f"No standard Sigma logsource for {primary}; skeleton uses a placeholder logsource."
        )

    selection: dict[str, list[str]] = {}
    for fld, op, literal in _PREDICATE_RE.findall(query):
        key = field_map.get(fld, fld) + _OP_MODIFIER[op]
        if fld in {"FileName", "InitiatingProcessFileName"} and field_map is _PROCESS_FIELDS:
            key = field_map[fld] + "|endswith"
        selection.setdefault(key, []).append(_unquote(literal))
    for fld, raw_items in _IN_RE.findall(query):
        items = [_unquote(m.group(0)) for m in _STRING_RE.finditer(raw_items)]
        if items:
            selection.setdefault(field_map.get(fld, fld), []).extend(items)

    lines = [
        f"title: {_yaml_str(title)}",
        f"id: {uuid.uuid4()}",
        "status: experimental",
        "description: "
        + _yaml_str(
            "Skeleton generated by link_hunt_to_rule from a Defender XDR Advanced "
            "Hunting query. Review the detection logic before deploying."
        ),
        f"date: {datetime.now(tz=UTC).strftime('%Y-%m-%d')}",
        "logsource:",
        *(f"  {k}: {v}" for k, v in logsource.items()),
        "detection:",
        "  selection:",
    ]
    if selection:
        for key, values in selection.items():
            if len(values) == 1:
                lines.append(f"    {_yaml_str(key)}: {_yaml_str(values[0])}")
            else:
                lines.append(f"    {_yaml_str(key)}:")
                lines.extend(f"      - {_yaml_str(v)}" for v in values)
    else:
        lines.append('    "TODO_Field": "TODO_value"')
        warnings.append(
            'No simple `field == "value"` predicates found; fill in detection.selection by hand.'
        )
    lines += [
        "  condition: selection",
        "falsepositives:",
        "  - Unknown",
        "level: medium",
        "",
    ]
    return "\n".join(lines)


def link_hunt(query: str, *, title: str) -> HuntLinkResult:
    rewritten, sources, targets, tmap, cmap, warnings = retarget_query(query)
    skeleton = build_sigma_skeleton(query, sources, title=title, warnings=warnings)
    return HuntLinkResult(
        sentinel_query=rewritten,
        source_tables=sources,
        target_tables=targets,
        table_mappings=tmap,
        column_mappings=cmap,
        warnings=warnings,
        sigma_skeleton=skeleton,
    )
