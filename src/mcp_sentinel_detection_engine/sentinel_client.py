"""Async HTTP client for the Azure Log Analytics query API (Sentinel data plane)."""

from __future__ import annotations

import asyncio
import os
import secrets
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager
from types import TracebackType
from typing import Any, Self

import httpx

from .auth import DEFAULT_LOGANALYTICS_RESOURCE, TokenManager
from .errors import (
    AuthError,
    NotFoundError,
    RateLimitedError,
    UpstreamError,
)

_DEFAULT_TIMEOUT_SECONDS = 60.0
_MAX_RETRIES = 3
_RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
_USER_AGENT = (
    "mcp-sentinel-detection-engine/0.1 "
    "(+https://github.com/MFisher14/mcp-sentinel-detection-engine)"
)


def _default_base_url() -> str:
    return os.environ.get("LOGANALYTICS_API_BASE", DEFAULT_LOGANALYTICS_RESOURCE).rstrip("/")


def _parse_retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None
    if seconds < 0:
        return None
    return min(seconds, 60.0)


class SentinelClient(AbstractAsyncContextManager["SentinelClient"]):
    """Thin async wrapper around the Log Analytics query API."""

    def __init__(
        self,
        token_manager: TokenManager,
        *,
        workspace_id: str,
        base_url: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
        http_client: httpx.AsyncClient | None = None,
        max_retries: int = _MAX_RETRIES,
        tenant_key: str = "default",
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._token_manager = token_manager
        self._tenant_key = tenant_key
        self._workspace_id = workspace_id
        self._base_url = (base_url or _default_base_url()).rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._sleep: Callable[[float], Awaitable[None]] = sleep or asyncio.sleep
        self._owns_client = http_client is None
        self._http: httpx.AsyncClient = http_client or httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
        )

    @property
    def workspace_id(self) -> str:
        return self._workspace_id

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
        if self._owns_client:
            await self._http.aclose()

    async def query(
        self,
        kql: str,
        *,
        timespan: str | None = None,
        server_timeout_seconds: int = 60,
    ) -> dict[str, Any]:
        """Run a KQL query against this client's workspace.

        Returns the raw Log Analytics response: ``{"tables": [{"name", "columns", "rows"}]}``.
        """
        path = f"/v1/workspaces/{self._workspace_id}/query"
        body: dict[str, Any] = {"query": kql}
        if timespan is not None:
            body["timespan"] = timespan
        headers = {"Prefer": f"wait={server_timeout_seconds}"}
        return await self._request("POST", path, json=body, extra_headers=headers)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Mapping[str, Any] | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        url = self._build_url(path)
        attempt = 0
        retried_after_401 = False

        while True:
            token = self._token_manager.get_token(self._tenant_key)
            headers: dict[str, str] = {"Authorization": f"Bearer {token}"}
            if extra_headers is not None:
                headers.update(extra_headers)
            try:
                response = await self._http.request(
                    method,
                    url,
                    params=dict(params) if params else None,
                    json=dict(json) if json else None,
                    headers=headers,
                )
            except httpx.TimeoutException as exc:
                if attempt < self._max_retries:
                    await self._backoff(attempt, retry_after=None)
                    attempt += 1
                    continue
                raise UpstreamError("Log Analytics request timed out") from exc
            except httpx.HTTPError as exc:
                raise UpstreamError("Log Analytics network error") from exc

            if 200 <= response.status_code < 300:
                return self._parse_json(response)

            if response.status_code == 401 and not retried_after_401:
                retried_after_401 = True
                self._token_manager.invalidate(self._tenant_key)
                continue

            if response.status_code == 401:
                raise AuthError("Log Analytics rejected the access token")

            if response.status_code == 404:
                raise NotFoundError(
                    "Log Analytics returned 404 Not Found",
                    status_code=response.status_code,
                )

            if response.status_code in _RETRYABLE_STATUSES and attempt < self._max_retries:
                retry_after = _parse_retry_after(response.headers.get("Retry-After"))
                await self._backoff(attempt, retry_after=retry_after)
                attempt += 1
                continue

            if response.status_code == 429:
                raise RateLimitedError(
                    "Log Analytics rate limit exceeded; retries exhausted",
                    status_code=response.status_code,
                )

            raise UpstreamError(
                f"Log Analytics returned HTTP {response.status_code}",
                status_code=response.status_code,
            )

    def _build_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return f"{self._base_url}{path}"

    @staticmethod
    def _parse_json(response: httpx.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise UpstreamError("Log Analytics returned non-JSON response") from exc
        if not isinstance(payload, dict):
            raise UpstreamError("Log Analytics returned unexpected JSON shape")
        return payload

    async def _backoff(self, attempt: int, *, retry_after: float | None) -> None:
        if retry_after is not None:
            delay = retry_after
        else:
            cap_ms = min(2**attempt, 8) * 1000
            delay = secrets.randbelow(cap_ms + 1) / 1000.0
        await self._sleep(delay)
