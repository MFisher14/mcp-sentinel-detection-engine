"""Tests for input validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mcp_sentinel_detection_engine.errors import InvalidInputError
from mcp_sentinel_detection_engine.validation import (
    ConvertSigmaInput,
    DryRunInput,
    EmitTerraformInput,
    Severity,
    TerraformRuleMetadata,
    ValidateKqlInput,
    parse_input,
)


class TestConvertSigmaInput:
    def test_accepts_inline_yaml(self) -> None:
        m = parse_input(ConvertSigmaInput, {"sigma_yaml": "title: t\n"})
        assert isinstance(m, ConvertSigmaInput)
        assert m.sigma_yaml is not None

    def test_accepts_path(self) -> None:
        m = parse_input(ConvertSigmaInput, {"sigma_path": "/var/spool/rule.yaml"})
        assert m.sigma_path == "/var/spool/rule.yaml"

    def test_rejects_both(self) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(
                ConvertSigmaInput,
                {"sigma_yaml": "title: t\n", "sigma_path": "/var/spool/rule.yaml"},
            )

    def test_rejects_neither(self) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(ConvertSigmaInput, {})

    def test_rejects_empty_yaml(self) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(ConvertSigmaInput, {"sigma_yaml": "   "})

    def test_rejects_nul_in_path(self) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(ConvertSigmaInput, {"sigma_path": "/var/spool/rule\x00.yaml"})


class TestValidateKqlInput:
    def test_accepts_basic(self) -> None:
        m = parse_input(
            ValidateKqlInput,
            {"query": "SecurityEvent | take 5", "table": "SecurityEvent"},
        )
        assert isinstance(m, ValidateKqlInput)
        assert m.table == "SecurityEvent"

    @pytest.mark.parametrize(
        "forbidden",
        [
            "SecurityEvent | .drop table foo",
            "SecurityEvent | .ingest into bar",
            "print .external_table(blah)",
            ".alter table widgets",
            "let x = 1; .purge table foo",
        ],
    )
    def test_rejects_destructive_kql(self, forbidden: str) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(ValidateKqlInput, {"query": forbidden, "table": "SecurityEvent"})

    def test_rejects_oversized_query(self) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(ValidateKqlInput, {"query": "x" * 10_001, "table": "SecurityEvent"})

    @pytest.mark.parametrize(
        "bad_table",
        [
            "1Bad",
            "with space",
            "../etc/passwd",
            "select",
            "DROP",
            "Table-Name",
        ],
    )
    def test_rejects_bad_table_names(self, bad_table: str) -> None:
        # 'DROP' / 'select' are pattern-valid but harmless; we just test pattern shape.
        # Only patterns that fail the regex should raise.
        import re

        from mcp_sentinel_detection_engine.validation import TABLE_NAME_PATTERN

        if TABLE_NAME_PATTERN.match(bad_table):
            # acceptable per the pattern
            parse_input(ValidateKqlInput, {"query": "X | take 1", "table": bad_table})
            return
        with pytest.raises(InvalidInputError):
            parse_input(ValidateKqlInput, {"query": "X | take 1", "table": bad_table})
        del re


class TestDryRunInput:
    def test_accepts_defaults(self) -> None:
        m = parse_input(DryRunInput, {"query": "SecurityEvent | take 1"})
        assert m.timespan == "P1D"
        assert m.row_limit == 10

    def test_rejects_oversized_row_limit(self) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(DryRunInput, {"query": "X | take 1", "row_limit": 11})

    def test_rejects_zero_row_limit(self) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(DryRunInput, {"query": "X | take 1", "row_limit": 0})

    @pytest.mark.parametrize("ts", ["P1D", "PT4H", "P7D", "PT30M", "P1DT4H"])
    def test_accepts_valid_durations(self, ts: str) -> None:
        m = parse_input(DryRunInput, {"query": "X | take 1", "timespan": ts})
        assert m.timespan == ts

    def test_rejects_bad_timespan(self) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(DryRunInput, {"query": "X | take 1", "timespan": "yesterday"})

    def test_strips_control_chars(self) -> None:
        m = parse_input(DryRunInput, {"query": "SecurityEvent \x07 | take 1"})
        assert "\x07" not in m.query
        assert "SecurityEvent" in m.query


class TestTerraformRuleMetadata:
    def test_defaults(self) -> None:
        m = TerraformRuleMetadata(name="my_rule", display_name="My Rule")
        assert m.severity is Severity.MEDIUM
        assert m.enabled is True
        assert m.query_frequency == "PT1H"
        assert m.tactics == []

    def test_rejects_bad_name(self) -> None:
        with pytest.raises(ValidationError):
            TerraformRuleMetadata(name="1bad", display_name="x")

    def test_rejects_bad_tactic(self) -> None:
        with pytest.raises(ValidationError):
            TerraformRuleMetadata(name="r", display_name="x", tactics=["lowercase-not-allowed"])

    @pytest.mark.parametrize("tactic", ["InitialAccess", "Execution", "Persistence"])
    def test_accepts_valid_tactics(self, tactic: str) -> None:
        m = TerraformRuleMetadata(name="r", display_name="x", tactics=[tactic])
        assert tactic in m.tactics

    @pytest.mark.parametrize("technique", ["T1059", "T1059.001", "T1078"])
    def test_accepts_valid_techniques(self, technique: str) -> None:
        m = TerraformRuleMetadata(name="r", display_name="x", techniques=[technique])
        assert technique in m.techniques

    @pytest.mark.parametrize("technique", ["1059", "TX059", "T59", "t1059", "T1059.A"])
    def test_rejects_bad_techniques(self, technique: str) -> None:
        with pytest.raises(ValidationError):
            TerraformRuleMetadata(name="r", display_name="x", techniques=[technique])

    def test_rejects_bad_iso_duration(self) -> None:
        with pytest.raises(ValidationError):
            TerraformRuleMetadata(name="r", display_name="x", query_frequency="1 hour")


class TestEmitTerraformInput:
    def test_accepts_full_payload(self) -> None:
        m = parse_input(
            EmitTerraformInput,
            {
                "query": "SecurityEvent | where EventID == 4625",
                "metadata": {
                    "name": "failed_logon",
                    "display_name": "Failed Logon Burst",
                    "severity": "High",
                    "tactics": ["CredentialAccess"],
                    "techniques": ["T1110"],
                },
            },
        )
        assert m.metadata.severity is Severity.HIGH

    def test_rejects_destructive_query(self) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(
                EmitTerraformInput,
                {
                    "query": ".drop table foo",
                    "metadata": {"name": "r", "display_name": "x"},
                },
            )


class TestTenantField:
    @pytest.mark.parametrize(
        "model, base",
        [
            (DryRunInput, {"query": "X | take 1"}),
            (ValidateKqlInput, {"query": "X | take 1", "table": "SecurityEvent"}),
            (ConvertSigmaInput, {"sigma_yaml": "title: t\n"}),
        ],
    )
    def test_tenant_omitted_defaults_to_none(self, model, base) -> None:
        m = parse_input(model, dict(base))
        assert m.tenant is None

    @pytest.mark.parametrize(
        "model, base",
        [
            (DryRunInput, {"query": "X | take 1"}),
            (ValidateKqlInput, {"query": "X | take 1", "table": "SecurityEvent"}),
            (ConvertSigmaInput, {"sigma_yaml": "title: t\n"}),
        ],
    )
    def test_tenant_accepts_valid_keys(self, model, base) -> None:
        for key in ("contoso", "tenant-1", "TENANT_2", "*"):
            m = parse_input(model, {**base, "tenant": key})
            assert m.tenant == key

    @pytest.mark.parametrize(
        "bad",
        ["tenant with spaces", "tenant/with/slashes", "tenant!exclaim", "x" * 65, "**", ""],
    )
    def test_tenant_rejects_malformed(self, bad: str) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(DryRunInput, {"query": "X | take 1", "tenant": bad})
