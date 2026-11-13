"""Server registration covers every tool module."""

from __future__ import annotations

from mcp_sentinel_detection_engine import server


def test_all_tools_registered_with_handlers() -> None:
    names = [tool.name for tool in server._tool_definitions()]
    assert names == [
        "convert_sigma_to_kql",
        "validate_kql_against_schema",
        "dry_run_kql",
        "generate_sentinel_terraform",
        "list_deployed_sentinel_rules",
        "detect_rule_drift",
        "terraform_plan",
        "link_hunt_to_rule",
    ]
    assert set(server._HANDLERS) == set(names)
    for tool in server._tool_definitions():
        assert tool.inputSchema["type"] == "object"
        assert tool.inputSchema["additionalProperties"] is False
