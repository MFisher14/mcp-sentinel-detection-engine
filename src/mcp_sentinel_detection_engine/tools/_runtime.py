"""Shared runtime helpers for tool implementations."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from ..audit import audit, audit_error
from ..errors import ErrorCode, InvalidInputError, SentinelError
from ..sentinel_client import SentinelClient
from ..tool_context import ToolContext
from ..validation import FAN_OUT_TENANT

TenantCall = Callable[[SentinelClient], Awaitable[dict[str, Any]]]


def resolve_targets(ctx: ToolContext, tenant: str | None) -> list[str]:
    if tenant is None:
        return [ctx.default_tenant_key]
    if tenant == FAN_OUT_TENANT:
        tenants = ctx.available_tenants()
        if not tenants:
            raise InvalidInputError("Fan-out requested but no tenants are configured")
        return tenants
    available = set(ctx.available_tenants())
    if tenant not in available:
        raise InvalidInputError("Unknown tenant")
    return [tenant]


async def dispatch(
    ctx: ToolContext,
    tool_name: str,
    targets: list[str],
    call: TenantCall,
) -> dict[str, Any]:
    if len(targets) == 1:
        client = ctx.client_for(targets[0])
        return await call(client)

    semaphore = asyncio.Semaphore(ctx.max_fan_out)

    async def _one(tenant_key: str) -> dict[str, Any]:
        async with semaphore:
            try:
                client = ctx.client_for(tenant_key)
                payload = await call(client)
            except SentinelError as exc:
                audit_error(
                    "fan-out-tenant-failed",
                    tool=tool_name,
                    tenant=tenant_key,
                    error_code=exc.code.value,
                    error_class=exc.__class__.__name__,
                )
                return {
                    "tenant": tenant_key,
                    "error": {"code": exc.code.value, "message": exc.public_message},
                }
            except Exception as exc:
                audit_error(
                    "fan-out-tenant-unhandled",
                    tool=tool_name,
                    tenant=tenant_key,
                    error_class=exc.__class__.__name__,
                )
                return {
                    "tenant": tenant_key,
                    "error": {
                        "code": ErrorCode.INTERNAL_ERROR.value,
                        "message": "An internal error occurred for this tenant.",
                    },
                }
            audit(
                "fan-out-tenant-succeeded",
                tool=tool_name,
                tenant=tenant_key,
            )
            return {"tenant": tenant_key, "result": payload}

    results = await asyncio.gather(*(_one(t) for t in targets))
    return {
        "fan_out": True,
        "tenants": targets,
        "results": results,
    }
