"""Shared pytest fixtures."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from mcp_sentinel_detection_engine.auth import (
    DEFAULT_TENANT_KEY,
    AzureCredentials,
    CredentialProvider,
    TokenManager,
)


class FakeCredentialProvider(CredentialProvider):
    def __init__(
        self,
        credentials: dict[str, AzureCredentials] | None = None,
        *,
        default: str = DEFAULT_TENANT_KEY,
    ) -> None:
        if credentials is None:
            credentials = {
                DEFAULT_TENANT_KEY: AzureCredentials(
                    tenant_id="11111111-1111-1111-1111-111111111111",
                    client_id="22222222-2222-2222-2222-222222222222",
                    cert_path="/dev/null",
                    workspace_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                )
            }
        self._credentials = dict(credentials)
        self._default = default

    def get_credentials(self, tenant_key: str = DEFAULT_TENANT_KEY) -> AzureCredentials:
        resolved = self._default if tenant_key == DEFAULT_TENANT_KEY else tenant_key
        creds = self._credentials.get(resolved)
        if creds is None:
            from mcp_sentinel_detection_engine.errors import AuthError

            raise AuthError("Unknown tenant")
        return creds

    def list_tenants(self) -> list[str]:
        return sorted(self._credentials.keys())

    @property
    def default_tenant_key(self) -> str:
        return self._default


class FakeMsalApp:
    def __init__(self, *, results: list[dict[str, Any]] | None = None) -> None:
        self.results = (
            results if results is not None else [{"access_token": "token-1", "expires_in": 3600}]
        )
        self.calls = 0

    def acquire_token_for_client(self, scopes: list[str]) -> dict[str, Any]:
        del scopes
        idx = min(self.calls, len(self.results) - 1)
        self.calls += 1
        return self.results[idx]


@pytest.fixture
def fake_credentials() -> AzureCredentials:
    return AzureCredentials(
        tenant_id="11111111-1111-1111-1111-111111111111",
        client_id="22222222-2222-2222-2222-222222222222",
        cert_path="/dev/null",
        workspace_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    )


@pytest.fixture
def fake_provider(fake_credentials: AzureCredentials) -> FakeCredentialProvider:
    return FakeCredentialProvider({DEFAULT_TENANT_KEY: fake_credentials})


@pytest.fixture
def fake_msal_app() -> FakeMsalApp:
    return FakeMsalApp()


@pytest.fixture
def token_manager(
    fake_provider: FakeCredentialProvider, fake_msal_app: FakeMsalApp
) -> TokenManager:
    def factory(**_: Any) -> Any:
        return fake_msal_app

    return TokenManager(fake_provider, msal_factory=factory)


def _build_context_factory(token_mgr: TokenManager):
    from mcp_sentinel_detection_engine.tool_context import ToolContext

    sleeps: list[float] = []

    async def _sleep(seconds: float) -> None:
        sleeps.append(seconds)

    def factory(handler, *, max_fan_out: int = 5):
        transport = httpx.MockTransport(handler)
        http_client = httpx.AsyncClient(
            transport=transport,
            base_url="https://api.loganalytics.io",
        )
        ctx = ToolContext(token_mgr, http_client=http_client, max_fan_out=max_fan_out)
        original = ctx.client_for

        def patched_client_for(tenant_key: str):
            client = original(tenant_key)
            client._sleep = _sleep
            return client

        ctx.client_for = patched_client_for  # type: ignore[method-assign]
        return ctx, sleeps

    return factory


@pytest.fixture
def make_context(token_manager: TokenManager):
    return _build_context_factory(token_manager)


@pytest.fixture
def make_multi_tenant_context():
    class PerTenantMsalApp:
        def __init__(self, tag: str) -> None:
            self.tag = tag

        def acquire_token_for_client(self, scopes: list[str]) -> dict[str, Any]:
            del scopes
            return {"access_token": f"token-{self.tag}", "expires_in": 3600}

    provider = FakeCredentialProvider(
        {
            "contoso": AzureCredentials(
                tenant_id="11111111-1111-1111-1111-111111111111",
                client_id="22222222-2222-2222-2222-222222222222",
                cert_path="/dev/null",
                workspace_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            ),
            "fabrikam": AzureCredentials(
                tenant_id="33333333-3333-3333-3333-333333333333",
                client_id="44444444-4444-4444-4444-444444444444",
                cert_path="/dev/null",
                workspace_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            ),
        },
        default="contoso",
    )

    def msal_factory(*, client_id: str, **_: Any) -> Any:
        tag = "contoso" if client_id.startswith("2222") else "fabrikam"
        return PerTenantMsalApp(tag)

    token_mgr = TokenManager(provider, msal_factory=msal_factory)
    return _build_context_factory(token_mgr)
