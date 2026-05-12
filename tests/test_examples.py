"""Smoke tests for the bundled Sigma examples under ``examples/sigma/``.

Every file in that directory must convert successfully via the
``convert_sigma_to_kql`` tool — including the adversarial rule whose
narrative fields contain prompt-injection bait, zero-width spaces, and a
bidi override character. That conversion succeeding is what demonstrates
the T1 mitigation chain documented in ``THREAT_MODEL.md``: control / format
characters are stripped at the validation boundary before pySigma sees
them, and the rule's narrative cannot drive a follow-up tool call from
inside the server.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mcp_sentinel_detection_engine.tools import convert_sigma

_EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples" / "sigma"

# Rules whose logsource does not have a built-in azure_monitor mapping need
# an explicit ``target_table``. The remaining files (failed_logon_burst.yml
# and adversarial/*.yml) use ``product: windows, service: security``, which
# pySigma auto-maps to SecurityEvent.
_TARGET_TABLES: dict[str, str] = {
    "aad_risky_signin.yml": "SigninLogs",
    "aad_privileged_role_assignment.yml": "AuditLogs",
    "o365_inbox_rule_creation.yml": "OfficeActivity",
    "azure_activity_keyvault_secret_get.yml": "AzureActivity",
    "linux_sudo_to_root.yml": "Syslog",
}


def _discover_examples() -> list[Path]:
    return sorted(_EXAMPLES_DIR.rglob("*.yml"))


@pytest.mark.parametrize(
    "rule_path",
    _discover_examples(),
    ids=lambda p: str(p.relative_to(_EXAMPLES_DIR)),
)
async def test_example_rule_converts(rule_path: Path) -> None:
    yaml_text = rule_path.read_text(encoding="utf-8")  # noqa: ASYNC240
    raw: dict[str, Any] = {"sigma_yaml": yaml_text}
    target = _TARGET_TABLES.get(rule_path.name)
    if target is not None:
        raw["target_table"] = target

    result = await convert_sigma.run(ctx=None, raw_params=raw)  # type: ignore[arg-type]

    assert result["metadata"]["query_count"] >= 1
    assert result["queries"][0]["kql"].strip(), "converter returned empty KQL"


def test_examples_directory_is_non_empty() -> None:
    rules = _discover_examples()
    assert rules, "examples/sigma/ should contain at least one rule"
    assert any(p.parent.name == "adversarial" for p in rules), (
        "expected the adversarial T1 demo rule under examples/sigma/adversarial/"
    )
