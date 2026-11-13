"""``terraform_plan`` tool implementation — plan only, never apply."""

from __future__ import annotations

import os
from typing import Annotated, Any

from pydantic import Field

from .. import terraform_runner
from ..audit import audit_tool_call
from ..errors import AuthError, InvalidInputError, SentinelError
from ..hcl_parse import MAX_HCL_LENGTH
from ..tool_context import ToolContext
from ..validation import FAN_OUT_TENANT, _TenantField, parse_input

TOOL_NAME = "terraform_plan"
TOOL_DESCRIPTION = (
    "Run ``terraform plan`` (NEVER ``apply``) on HCL produced by "
    "``generate_sentinel_terraform`` so you can see what a deployment would "
    "change before recommending it. The HCL must contain only "
    "``azurerm_sentinel_alert_rule_scheduled`` resources with literal values — "
    "provisioners, data sources, modules and interpolation are rejected. "
    "Terraform runs as a subprocess in a throwaway directory under a separate "
    "plan identity taken from the operator's ``ARM_*`` environment and the "
    "backend configured via ``MCP_SENTINEL_TF_BACKEND_CONFIG``; this server's "
    "own credentials are never passed to Terraform. Returns the plan summary "
    "(``add`` / ``change`` / ``destroy``), the planned resource changes, the "
    "plan text and any errors. Applying the plan is a human step outside "
    "Claude. ``log_analytics_workspace_id`` defaults to the tenant's configured "
    'workspace resource ID. Fan-out (``tenant: "*"``) is not supported.'
)

INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "hcl": {
            "type": "string",
            "description": "HCL from generate_sentinel_terraform (one or more rule blocks).",
            "minLength": 1,
            "maxLength": MAX_HCL_LENGTH,
        },
        "log_analytics_workspace_id": {
            "type": "string",
            "description": (
                "ARM resource ID of the target workspace. Defaults to the tenant's "
                "subscription_id / resource_group / workspace_name config."
            ),
            "maxLength": 512,
        },
        "tenant": {
            "type": "string",
            "description": "Tenant whose workspace to default to. '*' is not supported.",
            "pattern": r"^[A-Za-z0-9_-]{1,64}$",
        },
    },
    "required": ["hcl"],
    "additionalProperties": False,
}


class TerraformPlanInput(_TenantField):
    hcl: Annotated[str, Field(min_length=1, max_length=MAX_HCL_LENGTH)]
    log_analytics_workspace_id: Annotated[str, Field(min_length=1, max_length=512)] | None = None


def _configured_client_ids(ctx: ToolContext) -> set[str]:
    ids: set[str] = set()
    try:
        tenants = ctx.available_tenants()
    except AuthError:
        # Unconfigured host (LazyCredentialProvider): no server identity to clash with.
        return ids
    for key in tenants:
        try:
            ids.add(ctx.token_manager.get_credentials(key).client_id.lower())
        except SentinelError:
            continue
    return ids


def _resolve_workspace_id(ctx: ToolContext, params: TerraformPlanInput) -> str:
    if params.log_analytics_workspace_id is not None:
        return params.log_analytics_workspace_id
    try:
        tenant_key = params.tenant or ctx.default_tenant_key
        management = ctx.token_manager.get_credentials(tenant_key).management
    except AuthError as exc:
        raise InvalidInputError(
            "log_analytics_workspace_id is required when no tenant is configured"
        ) from exc
    if management is None:
        raise InvalidInputError(
            "log_analytics_workspace_id is required: the tenant has no "
            "subscription_id / resource_group / workspace_name configured"
        )
    return management.workspace_resource_id


async def run(ctx: ToolContext, raw_params: dict[str, Any]) -> dict[str, Any]:
    params = parse_input(TerraformPlanInput, raw_params)
    if params.tenant == FAN_OUT_TENANT:
        raise InvalidInputError("terraform_plan does not support tenant fan-out")
    if params.tenant is not None and params.tenant not in ctx.available_tenants():
        raise InvalidInputError("Unknown tenant")
    workspace_id = _resolve_workspace_id(ctx, params)

    env = dict(os.environ)
    plan_client_id = env.get("ARM_CLIENT_ID", "").strip().lower()
    if plan_client_id and plan_client_id in _configured_client_ids(ctx):
        raise InvalidInputError(
            "ARM_CLIENT_ID matches an App Registration this server queries with; "
            "terraform_plan must run under a separate identity."
        )

    audit_params = {
        "hcl_sha256": terraform_runner.hcl_sha256(params.hcl),
        "hcl_length": len(params.hcl),
        "workspace_resource_id": workspace_id,
        "backend_configured": bool(env.get(terraform_runner.BACKEND_CONFIG_ENV)),
    }
    with audit_tool_call(TOOL_NAME, audit_params) as audit_extra:
        result = await terraform_runner.run_plan(
            params.hcl, workspace_resource_id=workspace_id, env_source=env
        )
        audit_extra["success"] = result["success"]
        audit_extra["stage"] = result["stage"]
        audit_extra["summary"] = result["summary"]
        result["metadata"] = {
            "hcl_sha256": audit_params["hcl_sha256"],
            "workspace_resource_id": workspace_id,
        }
        return result
