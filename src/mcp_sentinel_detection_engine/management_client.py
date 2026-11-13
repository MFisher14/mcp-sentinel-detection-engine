"""Read-only async client for the Sentinel management plane (Azure Resource Manager).

Only ``GET`` is exposed. The server never creates, updates or deletes
Sentinel resources; rule deployment stays in a separate, human-gated
``terraform apply`` pipeline (see ``THREAT_MODEL.md`` T8).
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from urllib.parse import quote

import httpx

from .auth import (
    DEFAULT_MANAGEMENT_RESOURCE,
    DEFAULT_MANAGEMENT_SCOPE,
    ManagementTarget,
    TokenManager,
)
from .errors import UpstreamError
from .sentinel_client import AzureRestClient

SECURITY_INSIGHTS_API_VERSION = "2024-09-01"
MAX_PAGES = 20


def _default_base_url() -> str:
    return os.environ.get("AZURE_MANAGEMENT_API_BASE", DEFAULT_MANAGEMENT_RESOURCE).rstrip("/")


class ManagementClient(AzureRestClient):
    """GET-only wrapper over ``Microsoft.SecurityInsights`` alert-rule endpoints."""

    _service_name = "Azure Resource Manager"
    _scope = DEFAULT_MANAGEMENT_SCOPE

    def __init__(
        self,
        token_manager: TokenManager,
        *,
        target: ManagementTarget,
        base_url: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        tenant_key: str = "default",
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        super().__init__(
            token_manager,
            base_url=base_url or _default_base_url(),
            http_client=http_client,
            tenant_key=tenant_key,
            sleep=sleep,
        )
        self._target = target

    @property
    def target(self) -> ManagementTarget:
        return self._target

    def _alert_rules_path(self) -> str:
        t = self._target
        return (
            f"/subscriptions/{quote(t.subscription_id, safe='')}"
            f"/resourceGroups/{quote(t.resource_group, safe='')}"
            "/providers/Microsoft.OperationalInsights"
            f"/workspaces/{quote(t.workspace_name, safe='')}"
            "/providers/Microsoft.SecurityInsights/alertRules"
        )

    async def get(self, path: str, *, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return await self._request("GET", path, params=params)

    async def list_alert_rules(self, *, max_items: int | None = None) -> list[dict[str, Any]]:
        """Return raw alert-rule resources, following ``nextLink`` pagination.

        Stops once ``max_items`` raw items have been collected (if given), when
        there is no ``nextLink``, or after :data:`MAX_PAGES` pages.
        """
        items: list[dict[str, Any]] = []
        payload = await self.get(
            self._alert_rules_path(), params={"api-version": SECURITY_INSIGHTS_API_VERSION}
        )
        pages = 1
        while True:
            values = payload.get("value")
            if not isinstance(values, list):
                raise UpstreamError("Azure Resource Manager returned unexpected alert-rule shape")
            items.extend(v for v in values if isinstance(v, dict))
            if max_items is not None and len(items) >= max_items:
                break
            next_link = payload.get("nextLink")
            if not isinstance(next_link, str) or not next_link or pages >= MAX_PAGES:
                break
            # nextLink already carries api-version; _build_url enforces same-origin.
            payload = await self.get(next_link)
            pages += 1
        return items

    async def get_alert_rule(self, rule_id: str) -> dict[str, Any]:
        path = f"{self._alert_rules_path()}/{quote(rule_id, safe='')}"
        return await self.get(path, params={"api-version": SECURITY_INSIGHTS_API_VERSION})
