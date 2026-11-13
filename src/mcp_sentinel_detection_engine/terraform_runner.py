"""Run ``terraform plan`` (never ``apply``) against emitted rule HCL.

Security properties (see ``THREAT_MODEL.md`` T9):

- The ``terraform`` binary is resolved with :func:`shutil.which` and executed
  argv-only via :func:`asyncio.create_subprocess_exec` — no shell.
- Each run gets a fresh :func:`tempfile.mkdtemp` directory that is removed in
  a ``finally`` block, including on timeout.
- The input HCL must pass :func:`hcl_parse.parse_rules`, which only admits
  ``azurerm_sentinel_alert_rule_scheduled`` resources with literal values.
  No provisioners, data sources, modules, locals or interpolation reach
  Terraform.
- The child environment is an allowlist: ``ARM_*`` (the *plan* identity),
  proxy/TLS settings and the plugin cache. The MCP server's own ``AZURE_*``
  certificate variables, passphrases and tenants file never cross over, and
  ``HOME`` points at the scratch directory so no Azure CLI login is picked up.
- The only commands ever run are ``init``, ``plan`` and ``show``.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import re
import shutil
import signal
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import InvalidInputError, UpstreamError
from .hcl_parse import parse_rules

BACKEND_CONFIG_ENV = "MCP_SENTINEL_TF_BACKEND_CONFIG"
INIT_TIMEOUT_SECONDS = 180.0
PLAN_TIMEOUT_SECONDS = 300.0
SHOW_TIMEOUT_SECONDS = 60.0
MAX_OUTPUT_CHARS = 20_000
MAX_RESOURCE_CHANGES = 100

_ENV_PASSTHROUGH_EXACT = frozenset(
    {
        "PATH",
        "TF_PLUGIN_CACHE_DIR",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "https_proxy",
        "http_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    }
)
_ENV_PASSTHROUGH_PREFIXES = ("ARM_",)

_PLAN_SUMMARY_RE = re.compile(r"Plan: (\d+) to add, (\d+) to change, (\d+) to destroy")
_WORKSPACE_RESOURCE_ID_RE = re.compile(
    r"^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[-\w.()]{1,90}"
    r"/providers/Microsoft\.OperationalInsights/workspaces/[A-Za-z0-9-]{4,63}$"
)

_PROVIDERS_TF = """terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}
"""

_VARIABLES_TF = """variable "log_analytics_workspace_id" {
  type        = string
  description = "ARM resource ID of the Sentinel-enabled Log Analytics workspace."
}
"""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


async def _run_command(
    argv: list[str], *, cwd: str, env: Mapping[str, str], limit_seconds: float
) -> CommandResult:
    proc = await asyncio.create_subprocess_exec(
        *argv,
        cwd=cwd,
        env=dict(env),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        # Own process group so a timeout also kills provider plugin children.
        start_new_session=True,
    )
    try:
        async with asyncio.timeout(limit_seconds):
            stdout, stderr = await proc.communicate()
    except TimeoutError as exc:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            if hasattr(os, "killpg"):
                os.killpg(proc.pid, signal.SIGKILL)
            else:  # pragma: no cover - Windows
                proc.kill()
        await proc.wait()
        raise UpstreamError(f"terraform {argv[1]} timed out after {int(limit_seconds)}s") from exc
    return CommandResult(
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout.decode("utf-8", errors="replace"),
        stderr=stderr.decode("utf-8", errors="replace"),
    )


def hcl_sha256(hcl: str) -> str:
    return hashlib.sha256(hcl.encode("utf-8")).hexdigest()


def build_child_env(source: Mapping[str, str], workdir: str) -> dict[str, str]:
    env = {
        k: v
        for k, v in source.items()
        if k in _ENV_PASSTHROUGH_EXACT or k.startswith(_ENV_PASSTHROUGH_PREFIXES)
    }
    env.update(
        {
            "HOME": workdir,
            "TF_IN_AUTOMATION": "1",
            "TF_INPUT": "0",
            "CHECKPOINT_DISABLE": "1",
        }
    )
    return env


def validate_workspace_resource_id(value: str) -> str:
    if not _WORKSPACE_RESOURCE_ID_RE.match(value):
        raise InvalidInputError(
            "log_analytics_workspace_id must be an ARM workspace resource ID "
            "(/subscriptions/<guid>/resourceGroups/<rg>/providers/"
            "Microsoft.OperationalInsights/workspaces/<name>)"
        )
    return value


def _read_backend_config(source: Mapping[str, str]) -> str | None:
    raw = source.get(BACKEND_CONFIG_ENV)
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute() or not path.is_file():
        raise InvalidInputError(f"{BACKEND_CONFIG_ENV} must be an absolute path to a file")
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InvalidInputError(f"{BACKEND_CONFIG_ENV} could not be read") from exc


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[-MAX_OUTPUT_CHARS:]


def _parse_summary(stdout: str) -> dict[str, int] | None:
    match = _PLAN_SUMMARY_RE.search(stdout)
    if match is not None:
        add, change, destroy = (int(g) for g in match.groups())
        return {"add": add, "change": change, "destroy": destroy}
    if "No changes." in stdout:
        return {"add": 0, "change": 0, "destroy": 0}
    return None


def _extract_resource_changes(show_stdout: str) -> tuple[list[dict[str, Any]], bool]:
    try:
        payload = json.loads(show_stdout)
    except ValueError as exc:
        raise UpstreamError("terraform show -json returned invalid JSON") from exc
    raw = payload.get("resource_changes") if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return [], False
    changes: list[dict[str, Any]] = []
    for item in raw[:MAX_RESOURCE_CHANGES]:
        if not isinstance(item, dict):
            continue
        change = item.get("change")
        actions = change.get("actions") if isinstance(change, dict) else None
        changes.append(
            {
                "address": item.get("address"),
                "type": item.get("type"),
                "name": item.get("name"),
                "actions": actions if isinstance(actions, list) else [],
            }
        )
    return changes, len(raw) > MAX_RESOURCE_CHANGES


def _failure(stage: str, result: CommandResult, **extra: Any) -> dict[str, Any]:
    return {
        "success": False,
        "stage": stage,
        "summary": None,
        "resource_changes": [],
        "plan_output": _truncate(result.stdout),
        "errors": _truncate(result.stderr),
        **extra,
    }


async def run_plan(
    hcl: str,
    *,
    workspace_resource_id: str,
    env_source: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Validate ``hcl`` and run ``terraform init`` / ``plan`` / ``show -json``."""
    source: Mapping[str, str] = env_source if env_source is not None else os.environ
    rules = parse_rules(hcl)
    validate_workspace_resource_id(workspace_resource_id)
    terraform = shutil.which("terraform", path=source.get("PATH"))
    if terraform is None:
        raise InvalidInputError("terraform binary not found on PATH; install Terraform >= 1.5")
    backend = _read_backend_config(source)
    warnings: list[str] = []
    if backend is None:
        warnings.append(
            f"{BACKEND_CONFIG_ENV} is not set; planned against an empty local state, "
            "so every rule shows as a create."
        )

    workdir = tempfile.mkdtemp(prefix="mcp-sentinel-tfplan-")
    try:
        root = Path(workdir)
        (root / "providers.tf").write_text(_PROVIDERS_TF, encoding="utf-8")
        (root / "variables.tf").write_text(_VARIABLES_TF, encoding="utf-8")
        (root / "main.tf").write_text(hcl, encoding="utf-8")
        if backend is not None:
            (root / "backend.tf").write_text(backend, encoding="utf-8")
        env = build_child_env(source, workdir)
        common = {"rule_count": len(rules), "warnings": warnings}

        init = await _run_command(
            [terraform, "init", "-input=false", "-no-color"],
            cwd=workdir,
            env=env,
            limit_seconds=INIT_TIMEOUT_SECONDS,
        )
        if init.returncode != 0:
            return _failure("init", init, **common)

        plan = await _run_command(
            [
                terraform,
                "plan",
                "-input=false",
                "-no-color",
                "-lock=false",
                "-out=plan.bin",
                f"-var=log_analytics_workspace_id={workspace_resource_id}",
            ],
            cwd=workdir,
            env=env,
            limit_seconds=PLAN_TIMEOUT_SECONDS,
        )
        if plan.returncode != 0:
            return _failure("plan", plan, **common)

        show = await _run_command(
            [terraform, "show", "-json", "-no-color", "plan.bin"],
            cwd=workdir,
            env=env,
            limit_seconds=SHOW_TIMEOUT_SECONDS,
        )
        if show.returncode != 0:
            return _failure("show", show, **common)
        changes, truncated = _extract_resource_changes(show.stdout)
        return {
            "success": True,
            "stage": "complete",
            "summary": _parse_summary(plan.stdout),
            "resource_changes": changes,
            "resource_changes_truncated": truncated,
            "plan_output": _truncate(plan.stdout),
            "errors": _truncate(plan.stderr),
            **common,
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
