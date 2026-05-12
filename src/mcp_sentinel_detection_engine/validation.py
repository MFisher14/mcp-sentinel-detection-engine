"""Input validation and sanitization for tool parameters."""

from __future__ import annotations

import re
import unicodedata
from enum import StrEnum
from typing import Annotated, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .errors import InvalidInputError

T = TypeVar("T", bound=BaseModel)

MAX_KQL_LENGTH = 10_000
MAX_SIGMA_LENGTH = 50_000
MAX_RULE_NAME_LENGTH = 256
MAX_DESCRIPTION_LENGTH = 4_000
TENANT_KEY_PATTERN = re.compile(r"^([A-Za-z0-9_-]{1,64}|\*)$")
TABLE_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
ISO8601_DURATION_PATTERN = re.compile(
    r"^P(?!$)(\d+Y)?(\d+M)?(\d+W)?(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?$"
)
MITRE_TACTIC_PATTERN = re.compile(r"^[A-Z][A-Za-z]{1,63}$")
MITRE_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
GUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
FAN_OUT_TENANT = "*"

_KQL_FORBIDDEN_SUBSTRINGS = (
    ".external_table(",
    ".create-or-alter",
    ".alter",
    ".drop",
    ".set-or-append",
    ".ingest",
    ".purge",
    ".append",
    ".execute",
)


class Severity(StrEnum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


def _strip_control_chars(value: str) -> str:
    return "".join(
        ch for ch in value if ch == "\n" or ch == "\t" or unicodedata.category(ch)[0] != "C"
    )


def _validate_tenant_value(value: str | None) -> str | None:
    if value is None:
        return None
    if not TENANT_KEY_PATTERN.match(value):
        raise ValueError("tenant must match [A-Za-z0-9_-]{1,64} or be '*' for fan-out")
    return value


def _validate_kql_payload(value: str) -> str:
    cleaned = _strip_control_chars(value)
    if not cleaned.strip():
        raise ValueError("KQL query must contain non-whitespace characters")
    lowered = cleaned.lower()
    for forbidden in _KQL_FORBIDDEN_SUBSTRINGS:
        if forbidden in lowered:
            raise ValueError(
                f"KQL query contains a disallowed control verb ({forbidden!r}); "
                "only read-only Log Analytics queries are supported."
            )
    return cleaned


class _TenantField(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    tenant: str | None = None

    @field_validator("tenant")
    @classmethod
    def _check_tenant(cls, value: str | None) -> str | None:
        return _validate_tenant_value(value)


class ConvertSigmaInput(_TenantField):
    """Inputs for ``convert_sigma_to_kql``."""

    sigma_yaml: Annotated[str, Field(min_length=1, max_length=MAX_SIGMA_LENGTH)] | None = None
    sigma_path: Annotated[str, Field(min_length=1, max_length=4096)] | None = None
    target_table: Annotated[str, Field(min_length=1, max_length=128)] | None = None

    @field_validator("target_table")
    @classmethod
    def _validate_target_table(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not TABLE_NAME_PATTERN.match(value):
            raise ValueError("target_table must match [A-Za-z_][A-Za-z0-9_]{0,127}")
        return value

    @field_validator("sigma_yaml")
    @classmethod
    def _validate_yaml(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = _strip_control_chars(value)
        if not cleaned.strip():
            raise ValueError("sigma_yaml must contain non-whitespace content")
        return cleaned

    @field_validator("sigma_path")
    @classmethod
    def _validate_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if "\x00" in value:
            raise ValueError("sigma_path must not contain NUL bytes")
        return value

    def _post_init_check(self) -> None:
        if self.sigma_yaml is None and self.sigma_path is None:
            raise ValueError("provide either sigma_yaml or sigma_path")
        if self.sigma_yaml is not None and self.sigma_path is not None:
            raise ValueError("provide only one of sigma_yaml or sigma_path")

    def model_post_init(self, __context: object) -> None:
        self._post_init_check()


class ValidateKqlInput(_TenantField):
    """Inputs for ``validate_kql_against_schema``."""

    query: Annotated[str, Field(min_length=1, max_length=MAX_KQL_LENGTH)]
    table: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("query")
    @classmethod
    def _validate_query(cls, value: str) -> str:
        return _validate_kql_payload(value)

    @field_validator("table")
    @classmethod
    def _validate_table(cls, value: str) -> str:
        if not TABLE_NAME_PATTERN.match(value):
            raise ValueError("table must match [A-Za-z_][A-Za-z0-9_]{0,127}")
        return value


class DryRunInput(_TenantField):
    """Inputs for ``dry_run_kql``."""

    query: Annotated[str, Field(min_length=1, max_length=MAX_KQL_LENGTH)]
    timespan: Annotated[str, Field(min_length=2, max_length=32)] = "P1D"
    row_limit: Annotated[int, Field(ge=1, le=10)] = 10

    @field_validator("query")
    @classmethod
    def _validate_query(cls, value: str) -> str:
        return _validate_kql_payload(value)

    @field_validator("timespan")
    @classmethod
    def _validate_timespan(cls, value: str) -> str:
        if not ISO8601_DURATION_PATTERN.match(value):
            raise ValueError("timespan must be an ISO 8601 duration (e.g., 'P1D', 'PT4H', 'P7D')")
        return value


class TerraformRuleMetadata(BaseModel):
    """Pydantic v2 strict model for an ``azurerm_sentinel_alert_rule_scheduled`` block."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: Annotated[str, Field(min_length=1, max_length=MAX_RULE_NAME_LENGTH)]
    display_name: Annotated[str, Field(min_length=1, max_length=MAX_RULE_NAME_LENGTH)]
    description: Annotated[str, Field(max_length=MAX_DESCRIPTION_LENGTH)] = ""
    severity: Severity = Severity.MEDIUM
    enabled: bool = True
    query_frequency: Annotated[str, Field(min_length=2, max_length=32)] = "PT1H"
    query_period: Annotated[str, Field(min_length=2, max_length=32)] = "PT1H"
    trigger_operator: Annotated[str, Field(min_length=1, max_length=16)] = "GreaterThan"
    trigger_threshold: Annotated[int, Field(ge=0, le=10_000)] = 0
    suppression_enabled: bool = False
    suppression_duration: Annotated[str, Field(min_length=2, max_length=32)] = "PT1H"
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_-]{0,255}$", value):
            raise ValueError(
                "name must be a Terraform-safe identifier ([A-Za-z_][A-Za-z0-9_-]{0,255})"
            )
        return value

    @field_validator("query_frequency", "query_period", "suppression_duration")
    @classmethod
    def _validate_iso_duration(cls, value: str) -> str:
        if not ISO8601_DURATION_PATTERN.match(value):
            raise ValueError("must be an ISO 8601 duration (e.g., 'PT1H', 'P1D')")
        return value

    @field_validator("trigger_operator")
    @classmethod
    def _validate_trigger_op(cls, value: str) -> str:
        allowed = {"GreaterThan", "LessThan", "Equal", "NotEqual"}
        if value not in allowed:
            raise ValueError(f"trigger_operator must be one of {sorted(allowed)}")
        return value

    @field_validator("tactics")
    @classmethod
    def _validate_tactics(cls, value: list[str]) -> list[str]:
        for item in value:
            if not isinstance(item, str) or not MITRE_TACTIC_PATTERN.match(item):
                raise ValueError("each tactic must match [A-Z][A-Za-z]{1,63}")
        if len(value) > 32:
            raise ValueError("at most 32 tactics allowed")
        return value

    @field_validator("techniques")
    @classmethod
    def _validate_techniques(cls, value: list[str]) -> list[str]:
        for item in value:
            if not isinstance(item, str) or not MITRE_TECHNIQUE_PATTERN.match(item):
                raise ValueError("each technique must match Txxxx or Txxxx.yyy (MITRE ATT&CK)")
        if len(value) > 64:
            raise ValueError("at most 64 techniques allowed")
        return value


class EmitTerraformInput(_TenantField):
    """Inputs for ``generate_sentinel_terraform``."""

    query: Annotated[str, Field(min_length=1, max_length=MAX_KQL_LENGTH)]
    metadata: TerraformRuleMetadata

    @field_validator("query")
    @classmethod
    def _validate_query(cls, value: str) -> str:
        return _validate_kql_payload(value)


def parse_input(model: type[T], raw: dict[str, object]) -> T:
    try:
        return model.model_validate(raw)
    except Exception as exc:
        raise InvalidInputError(_format_validation_error(exc)) from exc


def _format_validation_error(exc: BaseException) -> str:
    errors_method = getattr(exc, "errors", None)
    if callable(errors_method):
        try:
            error_list = errors_method()
        except Exception:
            return "Invalid input"
        parts: list[str] = []
        for err in error_list:
            loc = ".".join(str(p) for p in err.get("loc", ())) or "<root>"
            msg = err.get("msg", "invalid value")
            parts.append(f"{loc}: {msg}")
        return "; ".join(parts) or "Invalid input"
    return "Invalid input"
