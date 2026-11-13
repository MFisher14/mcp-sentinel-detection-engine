"""Tests for ``terraform_plan`` — subprocess is always mocked."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path
from typing import Any

import httpx
import pytest

from mcp_sentinel_detection_engine import terraform_runner
from mcp_sentinel_detection_engine.errors import InvalidInputError, UpstreamError
from mcp_sentinel_detection_engine.terraform_emit import emit_terraform
from mcp_sentinel_detection_engine.terraform_runner import CommandResult, build_child_env
from mcp_sentinel_detection_engine.tools import terraform_plan
from mcp_sentinel_detection_engine.validation import TerraformRuleMetadata

from .conftest import MGMT_SUBSCRIPTION

HCL = emit_terraform(
    "SecurityEvent | where EventID == 4625",
    TerraformRuleMetadata(name="failed_logon", display_name="Failed logon"),
)
WS_ID = (
    f"/subscriptions/{MGMT_SUBSCRIPTION}/resourceGroups/rg-contoso/providers/"
    "Microsoft.OperationalInsights/workspaces/ws-contoso"
)
SHOW_JSON = json.dumps(
    {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": "azurerm_sentinel_alert_rule_scheduled.failed_logon",
                "type": "azurerm_sentinel_alert_rule_scheduled",
                "name": "failed_logon",
                "change": {"actions": ["create"], "after": {"secret": "x"}},
            }
        ],
    }
)


class FakeRunner:
    def __init__(self, results: dict[str, CommandResult] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.results = results or {}

    async def __call__(self, argv, *, cwd, env, limit_seconds) -> CommandResult:
        stage = argv[1]
        self.calls.append(
            {
                "argv": argv,
                "cwd": cwd,
                "env": dict(env),
                "files": {p.name: p.read_text() for p in Path(cwd).iterdir() if p.is_file()},  # noqa: ASYNC240
                "limit": limit_seconds,
            }
        )
        if stage in self.results:
            return self.results[stage]
        if stage == "plan":
            return CommandResult(0, "Plan: 1 to add, 0 to change, 0 to destroy.\n", "")
        if stage == "show":
            return CommandResult(0, SHOW_JSON, "")
        return CommandResult(0, "Terraform has been successfully initialized!", "")


@pytest.fixture
def fake_terraform(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeRunner:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    binary = bindir / "terraform"
    binary.write_text("#!/bin/sh\nexit 99\n")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(bindir))
    for key in list(os.environ):
        if key.startswith("ARM_") or key == terraform_runner.BACKEND_CONFIG_ENV:
            monkeypatch.delenv(key)
    runner = FakeRunner()
    monkeypatch.setattr(terraform_runner, "_run_command", runner)
    return runner


def _ctx(make_mgmt_context: Any) -> Any:
    return make_mgmt_context(lambda r: httpx.Response(500), include_bare=True)


async def test_plan_happy_path(make_mgmt_context, fake_terraform, monkeypatch, tmp_path) -> None:
    backend = tmp_path / "backend.tf"
    backend.write_text('terraform {\n  backend "azurerm" {}\n}\n')
    monkeypatch.setenv(terraform_runner.BACKEND_CONFIG_ENV, str(backend))
    monkeypatch.setenv("ARM_CLIENT_ID", "77777777-7777-7777-7777-777777777777")
    monkeypatch.setenv("AZURE_CERT_PASSPHRASE", "server-secret")
    monkeypatch.setenv("AZURE_CERT_PATH", "/secrets/server.pfx")
    monkeypatch.setenv("MCP_SENTINEL_TENANTS_FILE", "/etc/tenants.json")
    ctx = _ctx(make_mgmt_context)

    result = await terraform_plan.run(ctx, {"hcl": HCL})

    assert result["success"] is True
    assert result["summary"] == {"add": 1, "change": 0, "destroy": 0}
    assert result["resource_changes"] == [
        {
            "address": "azurerm_sentinel_alert_rule_scheduled.failed_logon",
            "type": "azurerm_sentinel_alert_rule_scheduled",
            "name": "failed_logon",
            "actions": ["create"],
        }
    ]
    assert result["warnings"] == []
    assert result["metadata"]["workspace_resource_id"] == WS_ID
    assert len(result["metadata"]["hcl_sha256"]) == 64

    stages = [c["argv"][1] for c in fake_terraform.calls]
    assert stages == ["init", "plan", "show"]
    assert "apply" not in json.dumps([c["argv"] for c in fake_terraform.calls])
    plan_argv = fake_terraform.calls[1]["argv"]
    assert f"-var=log_analytics_workspace_id={WS_ID}" in plan_argv
    assert "-lock=false" in plan_argv

    files = fake_terraform.calls[0]["files"]
    assert files["main.tf"].strip() == HCL.strip()
    assert 'backend "azurerm"' in files["backend.tf"]
    assert "required_providers" in files["providers.tf"]

    env = fake_terraform.calls[0]["env"]
    assert env["ARM_CLIENT_ID"] == "77777777-7777-7777-7777-777777777777"
    assert "AZURE_CERT_PASSPHRASE" not in env
    assert "AZURE_CERT_PATH" not in env
    assert "MCP_SENTINEL_TENANTS_FILE" not in env
    assert env["HOME"] == fake_terraform.calls[0]["cwd"]
    assert env["TF_IN_AUTOMATION"] == "1"

    # Scratch dir is removed after the run.
    assert not Path(fake_terraform.calls[0]["cwd"]).exists()  # noqa: ASYNC240
    await ctx.aclose()


async def test_plan_without_backend_warns(make_mgmt_context, fake_terraform) -> None:
    ctx = _ctx(make_mgmt_context)
    result = await terraform_plan.run(ctx, {"hcl": HCL, "log_analytics_workspace_id": WS_ID})
    assert result["success"] is True
    assert "empty local state" in result["warnings"][0]
    assert "backend.tf" not in fake_terraform.calls[0]["files"]
    await ctx.aclose()


@pytest.mark.parametrize("stage", ["init", "plan", "show"])
async def test_plan_stage_failure(make_mgmt_context, fake_terraform, stage) -> None:
    fake_terraform.results[stage] = CommandResult(1, "out", "Error: boom")
    ctx = _ctx(make_mgmt_context)
    result = await terraform_plan.run(ctx, {"hcl": HCL})
    assert result["success"] is False
    assert result["stage"] == stage
    assert result["errors"] == "Error: boom"
    assert not Path(fake_terraform.calls[0]["cwd"]).exists()  # noqa: ASYNC240
    await ctx.aclose()


async def test_plan_no_changes_summary(make_mgmt_context, fake_terraform) -> None:
    fake_terraform.results["plan"] = CommandResult(
        0, "No changes. Your infrastructure matches.", ""
    )
    ctx = _ctx(make_mgmt_context)
    result = await terraform_plan.run(ctx, {"hcl": HCL})
    assert result["summary"] == {"add": 0, "change": 0, "destroy": 0}
    await ctx.aclose()


async def test_plan_rejects_same_identity(make_mgmt_context, fake_terraform, monkeypatch) -> None:
    monkeypatch.setenv("ARM_CLIENT_ID", "22222222-2222-2222-2222-222222222222")
    ctx = _ctx(make_mgmt_context)
    with pytest.raises(InvalidInputError, match="separate identity"):
        await terraform_plan.run(ctx, {"hcl": HCL})
    assert fake_terraform.calls == []
    await ctx.aclose()


@pytest.mark.parametrize(
    ("params", "match"),
    [
        ({"hcl": 'resource "null_resource" "x" {\n}\n'}, "not allowed"),
        (
            {
                "hcl": 'resource "azurerm_sentinel_alert_rule_scheduled" "x" {\n'
                '  provisioner "local-exec" {\n    command = "id"\n  }\n}\n'
            },
            "nested blocks",
        ),
        ({"hcl": HCL, "tenant": "*"}, "fan-out"),
        ({"hcl": HCL, "tenant": "nobody"}, "Unknown tenant"),
        ({"hcl": HCL, "tenant": "bare"}, "log_analytics_workspace_id is required"),
        ({"hcl": HCL, "log_analytics_workspace_id": "/subscriptions/x"}, "ARM workspace"),
    ],
)
async def test_plan_rejects_bad_input(make_mgmt_context, fake_terraform, params, match) -> None:
    ctx = _ctx(make_mgmt_context)
    with pytest.raises(InvalidInputError, match=match):
        await terraform_plan.run(ctx, params)
    assert fake_terraform.calls == []
    await ctx.aclose()


async def test_plan_requires_terraform_binary(
    make_mgmt_context, fake_terraform, monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    ctx = _ctx(make_mgmt_context)
    with pytest.raises(InvalidInputError, match="terraform binary not found"):
        await terraform_plan.run(ctx, {"hcl": HCL})
    await ctx.aclose()


async def test_plan_bad_backend_path(make_mgmt_context, fake_terraform, monkeypatch) -> None:
    monkeypatch.setenv(terraform_runner.BACKEND_CONFIG_ENV, "relative/backend.tf")
    ctx = _ctx(make_mgmt_context)
    with pytest.raises(InvalidInputError, match="absolute path"):
        await terraform_plan.run(ctx, {"hcl": HCL})
    await ctx.aclose()


async def test_plan_offline_requires_workspace_id(fake_terraform, monkeypatch) -> None:
    # Production path on an unconfigured host: LazyCredentialProvider whose
    # factory raises AuthError on every access.
    from mcp_sentinel_detection_engine.auth import LazyCredentialProvider, TokenManager
    from mcp_sentinel_detection_engine.errors import AuthError
    from mcp_sentinel_detection_engine.tool_context import ToolContext

    def unconfigured() -> Any:
        raise AuthError("Missing required Azure credential environment variables")

    monkeypatch.setenv("ARM_CLIENT_ID", "99999999-9999-9999-9999-999999999999")
    async with ToolContext(TokenManager(LazyCredentialProvider(unconfigured))) as ctx:
        with pytest.raises(InvalidInputError, match="no tenant is configured"):
            await terraform_plan.run(ctx, {"hcl": HCL})
        result = await terraform_plan.run(ctx, {"hcl": HCL, "log_analytics_workspace_id": WS_ID})
        assert result["success"] is True


def test_build_child_env_allowlist() -> None:
    env = build_child_env(
        {
            "PATH": "/bin",
            "ARM_SUBSCRIPTION_ID": "s",
            "AZURE_CLIENT_ID": "server",
            "CONTOSO_CERT_PASS": "secret",
            "HOME": "/Users/me",
            "HTTPS_PROXY": "http://proxy",
        },
        "/scratch/work",
    )
    assert env == {
        "PATH": "/bin",
        "ARM_SUBSCRIPTION_ID": "s",
        "HTTPS_PROXY": "http://proxy",
        "HOME": "/scratch/work",
        "TF_IN_AUTOMATION": "1",
        "TF_INPUT": "0",
        "CHECKPOINT_DISABLE": "1",
    }


def test_extract_resource_changes_truncates_and_rejects_bad_json() -> None:
    many = json.dumps(
        {
            "resource_changes": [
                {"address": f"a{i}", "change": {"actions": ["create"]}} for i in range(150)
            ]
        }
    )
    changes, truncated = terraform_runner._extract_resource_changes(many)
    assert len(changes) == terraform_runner.MAX_RESOURCE_CHANGES
    assert truncated is True
    assert terraform_runner._extract_resource_changes("{}") == ([], False)
    with pytest.raises(UpstreamError):
        terraform_runner._extract_resource_changes("not json")
    assert terraform_runner._truncate("x" * 30_000) == "x" * terraform_runner.MAX_OUTPUT_CHARS


async def test_real_run_command_executes_argv_without_shell(tmp_path: Path) -> None:
    script = tmp_path / "echo.sh"
    script.write_text('#!/bin/sh\necho "args:$1"\necho err >&2\n')
    script.chmod(0o700)
    result = await terraform_runner._run_command(
        [str(script), "a; rm -rf /"],
        cwd=str(tmp_path),
        env={"PATH": "/bin:/usr/bin"},
        limit_seconds=10,
    )
    assert result == CommandResult(0, "args:a; rm -rf /\n", "err\n")


async def test_real_run_command_times_out(tmp_path: Path) -> None:
    script = tmp_path / "slow.sh"
    script.write_text("#!/bin/sh\nsleep 5\n")
    script.chmod(0o700)
    with pytest.raises(UpstreamError, match="timed out"):
        await terraform_runner._run_command(
            [str(script), "plan"],
            cwd=str(tmp_path),
            env={"PATH": "/bin:/usr/bin"},
            limit_seconds=0.2,
        )
    await asyncio.sleep(0)
