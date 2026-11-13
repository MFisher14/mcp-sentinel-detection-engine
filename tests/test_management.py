"""Management-plane plumbing: tenant config, scoped tokens, GET-only ARM client."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

from mcp_sentinel_detection_engine.auth import (
    DEFAULT_MANAGEMENT_SCOPE,
    AzureCredentials,
    EnvCredentialProvider,
    JsonFileCredentialProvider,
    ManagementTarget,
    TokenManager,
)
from mcp_sentinel_detection_engine.errors import AuthError, InvalidInputError, UpstreamError
from mcp_sentinel_detection_engine.management_client import ManagementClient
from mcp_sentinel_detection_engine.tool_context import ToolContext

from .conftest import FakeCredentialProvider

SUB = "99999999-9999-9999-9999-999999999999"
TARGET = ManagementTarget(
    subscription_id=SUB, resource_group="rg-sec", workspace_name="ws-sentinel"
)


def _base_env(tmp_path: Path) -> dict[str, str]:
    pfx = tmp_path / "cert.pfx"
    pfx.write_bytes(b"x")
    return {
        "AZURE_TENANT_ID": "11111111-1111-1111-1111-111111111111",
        "AZURE_CLIENT_ID": "22222222-2222-2222-2222-222222222222",
        "AZURE_CERT_PATH": str(pfx),
        "SENTINEL_WORKSPACE_ID": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    }


def test_env_provider_without_management_vars(tmp_path: Path) -> None:
    creds = EnvCredentialProvider(_base_env(tmp_path)).get_credentials()
    assert creds.management is None


def test_env_provider_reads_management_vars(tmp_path: Path) -> None:
    env = _base_env(tmp_path) | {
        "SENTINEL_SUBSCRIPTION_ID": SUB,
        "SENTINEL_RESOURCE_GROUP": "rg-sec",
        "SENTINEL_WORKSPACE_NAME": "ws-sentinel",
    }
    creds = EnvCredentialProvider(env).get_credentials()
    assert creds.management == TARGET
    assert creds.management.workspace_resource_id == (
        f"/subscriptions/{SUB}/resourceGroups/rg-sec/providers/"
        "Microsoft.OperationalInsights/workspaces/ws-sentinel"
    )


def test_env_provider_partial_management_vars_rejected(tmp_path: Path) -> None:
    env = _base_env(tmp_path) | {"SENTINEL_SUBSCRIPTION_ID": SUB}
    with pytest.raises(AuthError, match="must all be set together"):
        EnvCredentialProvider(env)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("subscription_id", "not-a-guid", "subscription_id must be a GUID"),
        ("resource_group", "bad/rg", "resource_group"),
        ("resource_group", "ends.", "resource_group"),
        ("workspace_name", "a", "workspace_name"),
        ("workspace_name", "ws/../x", "workspace_name"),
    ],
)
def test_json_provider_validates_management_fields(
    tmp_path: Path, field: str, value: str, match: str
) -> None:
    pfx = tmp_path / "c.pfx"
    pfx.write_bytes(b"x")
    entry: dict[str, Any] = {
        "tenant_id": "t",
        "client_id": "c",
        "cert_path": str(pfx),
        "workspace_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "subscription_id": SUB,
        "resource_group": "rg-sec",
        "workspace_name": "ws-sentinel",
    }
    entry[field] = value
    cfg = tmp_path / "tenants.json"
    cfg.write_text(json.dumps({"default": "a", "tenants": {"a": entry}}))
    os.chmod(cfg, 0o600)
    with pytest.raises(AuthError, match=match):
        JsonFileCredentialProvider(cfg, env={})


def test_json_provider_accepts_management_fields(tmp_path: Path) -> None:
    pfx = tmp_path / "c.pfx"
    pfx.write_bytes(b"x")
    cfg = tmp_path / "tenants.json"
    cfg.write_text(
        json.dumps(
            {
                "default": "a",
                "tenants": {
                    "a": {
                        "tenant_id": "t",
                        "client_id": "c",
                        "cert_path": str(pfx),
                        "workspace_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                        "subscription_id": SUB,
                        "resource_group": "rg-sec",
                        "workspace_name": "ws-sentinel",
                    }
                },
            }
        )
    )
    os.chmod(cfg, 0o600)
    creds = JsonFileCredentialProvider(cfg, env={}).get_credentials("a")
    assert creds.management == TARGET
    assert "management=" in repr(creds)


class _ScopeRecordingApp:
    def __init__(self) -> None:
        self.scopes: list[list[str]] = []

    def acquire_token_for_client(self, scopes: list[str]) -> dict[str, Any]:
        self.scopes.append(scopes)
        return {"access_token": f"tok-{len(self.scopes)}", "expires_in": 3600}


def test_token_manager_caches_per_scope(fake_provider: FakeCredentialProvider) -> None:
    app = _ScopeRecordingApp()
    manager = TokenManager(fake_provider, msal_factory=lambda **_: app)
    la = manager.get_token()
    mgmt = manager.get_token(scope=DEFAULT_MANAGEMENT_SCOPE)
    assert la != mgmt
    assert manager.get_token(scope=DEFAULT_MANAGEMENT_SCOPE) == mgmt
    assert app.scopes == [["https://api.loganalytics.io/.default"], [DEFAULT_MANAGEMENT_SCOPE]]
    manager.invalidate(scope=DEFAULT_MANAGEMENT_SCOPE)
    assert manager.get_token() == la
    assert manager.get_token(scope=DEFAULT_MANAGEMENT_SCOPE) != mgmt


def test_token_manager_rejects_unlisted_scope(fake_provider: FakeCredentialProvider) -> None:
    manager = TokenManager(fake_provider, msal_factory=lambda **_: _ScopeRecordingApp())
    with pytest.raises(AuthError, match="not permitted"):
        manager.get_token(scope="https://graph.microsoft.com/.default")


def _mgmt_client(handler: Any, token_manager: TokenManager) -> ManagementClient:
    async def _no_sleep(_: float) -> None:
        return None

    return ManagementClient(
        token_manager,
        target=TARGET,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        sleep=_no_sleep,
    )


async def test_management_client_paginates_and_uses_mgmt_token(
    token_manager: TokenManager,
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if "page2" in str(request.url):
            return httpx.Response(200, json={"value": [{"name": "r2"}]})
        return httpx.Response(
            200,
            json={
                "value": [{"name": "r1"}],
                "nextLink": "https://management.azure.com/next?page2=1&api-version=x",
            },
        )

    client = _mgmt_client(handler, token_manager)
    items = await client.list_alert_rules()
    assert [i["name"] for i in items] == ["r1", "r2"]
    assert seen[0].method == "GET"
    assert seen[0].url.path.endswith(
        "/resourceGroups/rg-sec/providers/Microsoft.OperationalInsights/"
        "workspaces/ws-sentinel/providers/Microsoft.SecurityInsights/alertRules"
    )
    assert seen[0].url.params["api-version"] == "2024-09-01"


async def test_management_client_stops_at_max_items(token_manager: TokenManager) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json={
                "value": [{"name": f"r{calls}"}],
                "nextLink": "https://management.azure.com/next",
            },
        )

    client = _mgmt_client(handler, token_manager)
    items = await client.list_alert_rules(max_items=3)
    assert len(items) == 3
    assert calls == 3


async def test_management_client_refuses_foreign_next_link(token_manager: TokenManager) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host != "management.azure.com":
            raise AssertionError("token sent to foreign host")
        return httpx.Response(200, json={"value": [], "nextLink": "https://evil.example.com/steal"})

    client = _mgmt_client(handler, token_manager)
    with pytest.raises(UpstreamError, match="unexpected host"):
        await client.list_alert_rules()


async def test_management_client_rejects_bad_shape(token_manager: TokenManager) -> None:
    client = _mgmt_client(lambda r: httpx.Response(200, json={"value": "nope"}), token_manager)
    with pytest.raises(UpstreamError, match="unexpected alert-rule shape"):
        await client.list_alert_rules()


async def test_management_client_get_rule_quotes_id(token_manager: TokenManager) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"name": "x"})

    client = _mgmt_client(handler, token_manager)
    await client.get_alert_rule("abc/../def")
    assert "abc%2F..%2Fdef" in str(seen[0].url)


async def test_management_client_for_requires_config(token_manager: TokenManager) -> None:
    async with ToolContext(token_manager) as ctx:
        with pytest.raises(InvalidInputError, match="not configured for Sentinel management"):
            ctx.management_client_for("default")


async def test_management_client_for_configured_tenant() -> None:
    provider = FakeCredentialProvider(
        {
            "default": AzureCredentials(
                tenant_id="t",
                client_id="c",
                cert_path="/dev/null",
                workspace_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                management=TARGET,
            )
        }
    )
    manager = TokenManager(provider, msal_factory=lambda **_: _ScopeRecordingApp())
    async with ToolContext(manager) as ctx:
        client = ctx.management_client_for("default")
        assert client.target == TARGET
        assert client.tenant_key == "default"
