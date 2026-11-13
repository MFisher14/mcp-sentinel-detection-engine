"""Per-call context handed to tool runners."""

from __future__ import annotations

from contextlib import AbstractAsyncContextManager
from types import TracebackType
from typing import Self

import httpx

from .auth import TokenManager
from .errors import InvalidInputError
from .management_client import ManagementClient
from .ratelimit import RateLimiter
from .sentinel_client import SentinelClient

_USER_AGENT = (
    "mcp-sentinel-detection-engine/0.1 "
    "(+https://github.com/MFisher14/mcp-sentinel-detection-engine)"
)


class ToolContext(AbstractAsyncContextManager["ToolContext"]):
    """Shared execution context for a single MCP tool call."""

    def __init__(
        self,
        token_manager: TokenManager,
        *,
        http_client: httpx.AsyncClient | None = None,
        max_fan_out: int = 5,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self._token_manager = token_manager
        self._owns_http = http_client is None
        self._http: httpx.AsyncClient = http_client or httpx.AsyncClient(
            headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
        )
        self._max_fan_out = max_fan_out
        self._rate_limiter = rate_limiter or RateLimiter(token_manager.rate_limit_configs())

    @property
    def token_manager(self) -> TokenManager:
        return self._token_manager

    @property
    def default_tenant_key(self) -> str:
        return self._token_manager.default_tenant_key

    @property
    def rate_limiter(self) -> RateLimiter:
        return self._rate_limiter

    @property
    def max_fan_out(self) -> int:
        return self._max_fan_out

    def available_tenants(self) -> list[str]:
        return self._token_manager.list_tenants()

    def client_for(self, tenant_key: str) -> SentinelClient:
        credentials = self._token_manager.get_credentials(tenant_key)
        return SentinelClient(
            self._token_manager,
            workspace_id=credentials.workspace_id,
            http_client=self._http,
            tenant_key=tenant_key,
        )

    def management_client_for(self, tenant_key: str) -> ManagementClient:
        """Return a GET-only Sentinel management-plane client for ``tenant_key``.

        Raises ``InvalidInputError`` if the tenant has no ``subscription_id`` /
        ``resource_group`` / ``workspace_name`` configured.
        """
        credentials = self._token_manager.get_credentials(tenant_key)
        if credentials.management is None:
            raise InvalidInputError(
                "This tenant is not configured for Sentinel management-plane access; "
                "set subscription_id, resource_group and workspace_name in the tenant "
                "config (or SENTINEL_SUBSCRIPTION_ID / SENTINEL_RESOURCE_GROUP / "
                "SENTINEL_WORKSPACE_NAME)."
            )
        return ManagementClient(
            self._token_manager,
            target=credentials.management,
            http_client=self._http,
            tenant_key=tenant_key,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        del exc_type, exc, tb
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()
