"""Tests for the Azure Key Vault PFX source (issue #10). No network."""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from mcp_sentinel_detection_engine.auth import JsonFileCredentialProvider, TokenManager
from mcp_sentinel_detection_engine.credentials import base as cred_base
from mcp_sentinel_detection_engine.credentials import load_pfx
from mcp_sentinel_detection_engine.credentials.keyvault import (
    AppRegistrationBootstrap,
    KeyVaultPfxSource,
    ManagedIdentityBootstrap,
    parse_key_vault_block,
    validate_vault_url,
)
from mcp_sentinel_detection_engine.errors import AuthError

from ._pfx_factory import make_pfx

_GUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
_VAULT = "https://contoso-kv.vault.azure.net"
_CERT = "mcp-sentinel-contoso"

Handler = Callable[[httpx.Request], httpx.Response]


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _kv_handler(
    pfx: bytes,
    *,
    seen: list[httpx.Request] | None = None,
    kv_status: int = 200,
    content_type: str | None = "application/x-pkcs12",
) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        host = request.url.host
        if host in ("169.254.169.254", "localhost"):
            return httpx.Response(200, json={"access_token": "mi-token", "expires_in": "3600"})
        if host.endswith("vault.azure.net"):
            if kv_status != 200:
                return httpx.Response(kv_status, json={"error": {"message": "denied"}})
            body: dict[str, Any] = {"value": base64.b64encode(pfx).decode()}
            if content_type is not None:
                body["contentType"] = content_type
            return httpx.Response(200, json=body)
        return httpx.Response(404)

    return handler


# --- URL validation -----------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "resource"),
    [
        ("https://contoso-kv.vault.azure.net", "https://vault.azure.net"),
        ("https://CONTOSO-kv.vault.azure.net/", "https://vault.azure.net"),
        ("https://kv.vault.azure.cn", "https://vault.azure.cn"),
        ("https://kv.vault.usgovcloudapi.net", "https://vault.usgovcloudapi.net"),
    ],
)
def test_validate_vault_url_accepts_known_clouds(url: str, resource: str) -> None:
    normalized, res = validate_vault_url(url, context="t")
    assert res == resource
    assert normalized.startswith("https://") and not normalized.endswith("/")


@pytest.mark.parametrize(
    "url",
    [
        "http://kv.vault.azure.net",
        "https://kv.vault.azure.net.evil.com",
        "https://evil.com/?x=.vault.azure.net",
        "https://vault.azure.net",
        "https://a.b.vault.azure.net",
        "https://kv.vault.azure.net:8443",
        "https://user@kv.vault.azure.net",
        "https://kv.vault.azure.net/secrets/x",
    ],
)
def test_validate_vault_url_rejects_without_echo(url: str) -> None:
    with pytest.raises(AuthError) as exc_info:
        validate_vault_url(url, context="t")
    assert url not in str(exc_info.value)


# --- Fetch --------------------------------------------------------------------


def test_fetch_with_managed_identity_imds() -> None:
    pfx = make_pfx()
    seen: list[httpx.Request] = []
    source = parse_key_vault_block(
        "contoso",
        {"url": _VAULT, "certificate_name": _CERT},
        {},
        http_client=_client(_kv_handler(pfx, seen=seen)),
    )
    assert isinstance(source.bootstrap, ManagedIdentityBootstrap)
    assert source.fetch_pfx() == pfx

    imds, kv = seen
    assert imds.url.host == "169.254.169.254"
    assert imds.headers["Metadata"] == "true"
    assert imds.url.params["resource"] == "https://vault.azure.net"
    assert kv.url.path == f"/secrets/{_CERT}"
    assert kv.url.params["api-version"] == "7.4"
    assert kv.headers["Authorization"] == "Bearer mi-token"


def test_fetch_with_app_service_identity_endpoint_and_user_assigned_id() -> None:
    pfx = make_pfx()
    seen: list[httpx.Request] = []
    env = {"IDENTITY_ENDPOINT": "http://localhost:4141/msi/token", "IDENTITY_HEADER": "hdr"}
    client_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    source = parse_key_vault_block(
        "contoso",
        {
            "url": _VAULT,
            "certificate_name": _CERT,
            "bootstrap_identity": {"type": "managed_identity", "client_id": client_id},
        },
        env,
        http_client=_client(_kv_handler(pfx, seen=seen)),
    )
    source.fetch_pfx()
    msi = seen[0]
    assert msi.url.host == "localhost"
    assert msi.headers["X-IDENTITY-HEADER"] == "hdr"
    assert msi.url.params["client_id"] == client_id
    assert msi.url.params["api-version"] == "2019-08-01"


def test_managed_identity_token_is_cached() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"access_token": "t", "expires_on": "9999999999"})

    mi = ManagedIdentityBootstrap(client_id=None, http_client=_client(handler), env={})
    assert mi.get_token("https://vault.azure.net") == "t"
    assert mi.get_token("https://vault.azure.net") == "t"
    assert calls["n"] == 1


@pytest.mark.parametrize(
    "response",
    [httpx.Response(400, json={}), httpx.Response(200, text="nope"), httpx.Response(200, json=[])],
)
def test_managed_identity_failures(response: httpx.Response) -> None:
    mi = ManagedIdentityBootstrap(client_id=None, http_client=_client(lambda _r: response), env={})
    with pytest.raises(AuthError, match="Managed identity"):
        mi.get_token("https://vault.azure.net")


def test_managed_identity_unreachable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    mi = ManagedIdentityBootstrap(client_id=None, http_client=_client(handler), env={})
    with pytest.raises(AuthError, match="unreachable"):
        mi.get_token("https://vault.azure.net")


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_fetch_http_errors_do_not_echo_vault_or_cert(status: int) -> None:
    source = parse_key_vault_block(
        "contoso",
        {"url": _VAULT, "certificate_name": _CERT},
        {},
        http_client=_client(_kv_handler(b"", kv_status=status)),
    )
    with pytest.raises(AuthError) as exc_info:
        source.fetch_pfx()
    message = str(exc_info.value)
    assert str(status) in message
    assert "contoso-kv" not in message
    assert _CERT not in message


def test_fetch_rejects_pem_content_type() -> None:
    source = parse_key_vault_block(
        "c",
        {"url": _VAULT, "certificate_name": _CERT},
        {},
        http_client=_client(_kv_handler(make_pfx(), content_type="application/x-pem-file")),
    )
    with pytest.raises(AuthError, match="PKCS#12"):
        source.fetch_pfx()


def test_fetch_rejects_non_base64_and_malformed() -> None:
    def bad_b64(request: httpx.Request) -> httpx.Response:
        if request.url.host.endswith("vault.azure.net"):
            return httpx.Response(200, json={"value": "!!!not-base64!!!"})
        return httpx.Response(200, json={"access_token": "t"})

    def bad_json(request: httpx.Request) -> httpx.Response:
        if request.url.host.endswith("vault.azure.net"):
            return httpx.Response(200, text="<html>")
        return httpx.Response(200, json={"access_token": "t"})

    for handler, match in ((bad_b64, "base64"), (bad_json, "malformed")):
        source = parse_key_vault_block(
            "c", {"url": _VAULT, "certificate_name": _CERT}, {}, http_client=_client(handler)
        )
        with pytest.raises(AuthError, match=match):
            source.fetch_pfx()


def test_fetch_network_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host.endswith("vault.azure.net"):
            raise httpx.ConnectError("down", request=request)
        return httpx.Response(200, json={"access_token": "t"})

    source = parse_key_vault_block(
        "c", {"url": _VAULT, "certificate_name": _CERT}, {}, http_client=_client(handler)
    )
    with pytest.raises(AuthError, match="network error"):
        source.fetch_pfx()


def test_fetch_decrypts_with_passphrase_env() -> None:
    pfx = make_pfx("pw")
    source = parse_key_vault_block(
        "c",
        {"url": _VAULT, "certificate_name": _CERT, "passphrase_env": "KV_PFX_PASS"},
        {"KV_PFX_PASS": "pw"},
        http_client=_client(_kv_handler(pfx)),
    )
    load_pfx(source.fetch_pfx(), None)


# --- App-registration bootstrap -------------------------------------------------


class _FakeApp:
    def __init__(self, result: dict[str, Any]) -> None:
        self.result = result
        self.scopes: list[list[str]] = []

    def acquire_token_for_client(self, scopes: list[str]) -> dict[str, Any]:
        self.scopes.append(scopes)
        return self.result


def test_app_registration_bootstrap(tmp_path: Path) -> None:
    boot_pfx = tmp_path / "boot.pfx"
    boot_pfx.write_bytes(b"x")
    app = _FakeApp({"access_token": "boot-token"})
    created: list[dict[str, Any]] = []

    def factory(**kwargs: Any) -> _FakeApp:
        created.append(kwargs)
        return app

    seen: list[httpx.Request] = []
    secret = base64.b64encode(make_pfx()).decode()

    def kv(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"value": secret})

    source = parse_key_vault_block(
        "c",
        {
            "url": "https://kv.vault.azure.cn",
            "certificate_name": _CERT,
            "bootstrap_identity": {
                "type": "app_registration",
                "tenant_id": "t",
                "client_id": "boot-client",
                "cert_path": str(boot_pfx),
                "cert_passphrase_env": "BOOT_PASS",
            },
        },
        {"BOOT_PASS": "bp"},
        http_client=_client(kv),
        msal_factory=factory,
    )
    assert isinstance(source.bootstrap, AppRegistrationBootstrap)
    source.fetch_pfx()
    assert app.scopes == [["https://vault.azure.cn/.default"]]
    assert created[0]["client_id"] == "boot-client"
    assert created[0]["client_credential"] == {
        "private_key_pfx_path": str(boot_pfx),
        "passphrase": "bp",
    }
    assert seen[0].headers["Authorization"] == "Bearer boot-token"


def test_app_registration_bootstrap_token_failure(tmp_path: Path) -> None:
    boot = AppRegistrationBootstrap(
        tenant_id="t",
        client_id="c",
        cert_path=str(tmp_path / "x.pfx"),
        cert_passphrase=None,
        msal_factory=lambda **_: _FakeApp({"error": "invalid_client"}),
    )
    with pytest.raises(AuthError, match="invalid_client"):
        boot.get_token("https://vault.azure.net")


def test_app_registration_bootstrap_init_failure() -> None:
    def factory(**_: Any) -> Any:
        raise ValueError("bad cert at /secret/path")

    boot = AppRegistrationBootstrap(
        tenant_id="t", client_id="c", cert_path="/x", cert_passphrase=None, msal_factory=factory
    )
    with pytest.raises(AuthError) as exc_info:
        boot.get_token("https://vault.azure.net")
    assert "/secret/path" not in str(exc_info.value)


# --- Config validation ----------------------------------------------------------


@pytest.mark.parametrize(
    ("block", "match"),
    [
        ({"certificate_name": _CERT}, "url"),
        ({"url": _VAULT}, "certificate_name"),
        ({"url": _VAULT, "certificate_name": "bad/name"}, "certificate_name"),
        ({"url": _VAULT, "certificate_name": _CERT, "extra": 1}, "unknown fields"),
        ({"url": _VAULT, "certificate_name": _CERT, "bootstrap_identity": "mi"}, "object"),
        (
            {"url": _VAULT, "certificate_name": _CERT, "bootstrap_identity": {"type": "x"}},
            "type must be",
        ),
        (
            {
                "url": _VAULT,
                "certificate_name": _CERT,
                "bootstrap_identity": {"type": "managed_identity", "client_id": "nope"},
            },
            "GUID",
        ),
        (
            {
                "url": _VAULT,
                "certificate_name": _CERT,
                "bootstrap_identity": {"type": "managed_identity", "foo": 1},
            },
            "unknown fields",
        ),
        (
            {
                "url": _VAULT,
                "certificate_name": _CERT,
                "bootstrap_identity": {
                    "type": "app_registration",
                    "tenant_id": "t",
                    "client_id": "c",
                    "cert_path": "/does/not/exist.pfx",
                },
            },
            "readable",
        ),
        (
            {
                "url": _VAULT,
                "certificate_name": _CERT,
                "bootstrap_identity": {"type": "app_registration", "bogus": 1},
            },
            "unknown fields",
        ),
        ({"url": _VAULT, "certificate_name": _CERT, "passphrase_env": "bad name"}, "environment"),
    ],
)
def test_parse_key_vault_block_rejects(block: dict[str, Any], match: str) -> None:
    with pytest.raises(AuthError, match=match):
        parse_key_vault_block("c", block, {}, http_client=_client(lambda r: httpx.Response(500)))


def test_missing_passphrase_env_value() -> None:
    source = parse_key_vault_block(
        "c",
        {"url": _VAULT, "certificate_name": _CERT, "passphrase_env": "KV_PASS"},
        {},
        http_client=_client(_kv_handler(make_pfx())),
    )
    with pytest.raises(AuthError) as exc_info:
        source.fetch_pfx()
    assert "KV_PASS" not in str(exc_info.value)


# --- Tenants JSON integration -----------------------------------------------------


def _write_config(tmp_path: Path, tenants: dict[str, Any]) -> Path:
    path = tmp_path / "tenants.json"
    path.write_text(json.dumps({"default": next(iter(tenants)), "tenants": tenants}))
    os.chmod(path, 0o600)
    return path


def test_tenants_json_key_vault_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pfx = make_pfx()
    monkeypatch.setattr(cred_base, "new_http_client", lambda: _client(_kv_handler(pfx)))
    path = _write_config(
        tmp_path,
        {
            "contoso": {
                "tenant_id": "11111111-1111-1111-1111-111111111111",
                "client_id": "22222222-2222-2222-2222-222222222222",
                "workspace_id": _GUID,
                "key_vault": {"url": _VAULT, "certificate_name": _CERT},
            }
        },
    )
    provider = JsonFileCredentialProvider(path, env={})
    creds = provider.get_credentials("contoso")
    assert creds.cert_path is None
    assert provider.get_pfx_bytes("contoso") == pfx

    received: list[dict[str, Any]] = []

    class _App:
        def acquire_token_for_client(self, scopes: list[str]) -> dict[str, Any]:
            return {"access_token": "la-token", "expires_in": 3600}

    def factory(**kwargs: Any) -> _App:
        received.append(kwargs["client_credential"])
        return _App()

    assert TokenManager(provider, msal_factory=factory).get_token("contoso") == "la-token"
    assert "private_key" in received[0]


def test_tenants_json_rejects_cert_path_and_key_vault(tmp_path: Path) -> None:
    pfx = tmp_path / "c.pfx"
    pfx.write_bytes(b"x")
    path = _write_config(
        tmp_path,
        {
            "a": {
                "tenant_id": "t",
                "client_id": "c",
                "workspace_id": _GUID,
                "cert_path": str(pfx),
                "key_vault": {"url": _VAULT, "certificate_name": _CERT},
            }
        },
    )
    with pytest.raises(AuthError, match="exactly one certificate source"):
        JsonFileCredentialProvider(path, env={})


def test_tenants_json_rejects_passphrase_with_key_vault(tmp_path: Path) -> None:
    path = _write_config(
        tmp_path,
        {
            "a": {
                "tenant_id": "t",
                "client_id": "c",
                "workspace_id": _GUID,
                "cert_passphrase_env": "X",
                "key_vault": {"url": _VAULT, "certificate_name": _CERT},
            }
        },
    )
    with pytest.raises(AuthError, match="passphrase inside that block"):
        JsonFileCredentialProvider(path, env={})


def test_tenants_json_key_vault_block_must_be_object(tmp_path: Path) -> None:
    path = _write_config(
        tmp_path,
        {"a": {"tenant_id": "t", "client_id": "c", "workspace_id": _GUID, "key_vault": "x"}},
    )
    with pytest.raises(AuthError, match="must be an object"):
        JsonFileCredentialProvider(path, env={})


def test_key_vault_source_store_label() -> None:
    assert KeyVaultPfxSource.store == "key_vault"
