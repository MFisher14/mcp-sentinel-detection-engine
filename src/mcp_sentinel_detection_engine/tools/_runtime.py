"""Shared runtime helpers for tool implementations."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from ..audit import audit, audit_error
from ..errors import ErrorCode, InvalidInputError, RateLimitedError, SentinelError
from ..sentinel_client import SentinelClient
from ..tool_context import ToolContext
from ..validation import FAN_OUT_TENANT

TenantCall = Callable[[SentinelClient], Awaitable[dict[str, Any]]]
ClientFactory = Callable[[str], Any]


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
    call: Callable[[Any], Awaitable[dict[str, Any]]],
    *,
    client_factory: ClientFactory | None = None,
) -> dict[str, Any]:
    """Run ``call`` once per target tenant.

    ``client_factory`` maps a tenant key to the client handed to ``call``; it
    defaults to the Log Analytics :class:`SentinelClient` (``ctx.client_for``).
    Management-plane tools pass ``ctx.management_client_for``. Every call,
    on either plane, goes through the per-tenant rate limiter.
    """
    make_client: ClientFactory = client_factory or ctx.client_for

    async def _guarded(tenant_key: str) -> dict[str, Any]:
        limiter = ctx.rate_limiter
        limiter.acquire(tenant_key, tool_name)
        client = make_client(tenant_key)
        try:
            payload = await call(client)
        except RateLimitedError:
            limiter.record_rate_limited(tenant_key)
            raise
        limiter.record_success(tenant_key)
        return payload

    if len(targets) == 1:
        return await _guarded(targets[0])

    semaphore = asyncio.Semaphore(ctx.max_fan_out)

    async def _one(tenant_key: str) -> dict[str, Any]:
        async with semaphore:
            try:
                payload = await _guarded(tenant_key)
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
