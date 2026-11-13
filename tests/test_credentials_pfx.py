"""Tests for the CredentialProvider.get_pfx_bytes abstraction (issue #9)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import msal
import pytest

from mcp_sentinel_detection_engine.auth import (
    DEFAULT_TENANT_KEY,
    AzureCredentials,
    CredentialProvider,
    JsonFileCredentialProvider,
    TokenManager,
    _build_client_credential,
)
from mcp_sentinel_detection_engine.credentials import (
    CachingPfxSource,
    PfxSource,
    load_pfx,
    normalize_pfx,
    pfx_to_msal_credential,
)
from mcp_sentinel_detection_engine.errors import AuthError, UpstreamError

from ._pfx_factory import make_pfx

_GUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def _creds(cert_path: str | None = None, passphrase: str | None = None) -> AzureCredentials:
    return AzureCredentials(
        tenant_id="11111111-1111-1111-1111-111111111111",
        client_id="22222222-2222-2222-2222-222222222222",
        cert_path=cert_path,
        workspace_id=_GUID,
        cert_passphrase=passphrase,
    )


class _BytesProvider(CredentialProvider):
    def __init__(self, pfx: bytes, passphrase: str | None = None) -> None:
        self.pfx = pfx
        self.passphrase = passphrase
        self.pfx_calls = 0

    def get_credentials(self, tenant_key: str = DEFAULT_TENANT_KEY) -> AzureCredentials:
        return _creds(passphrase=self.passphrase)

    def get_pfx_bytes(self, tenant_key: str = DEFAULT_TENANT_KEY) -> bytes | None:
        self.pfx_calls += 1
        return self.pfx


class _RecordingFactory:
    def __init__(self) -> None:
        self.credentials: list[dict[str, Any]] = []

    def __call__(self, *, client_id: str, authority: str, client_credential: dict[str, Any]) -> Any:
        del client_id, authority
        self.credentials.append(client_credential)
        return _FakeApp()


class _FakeApp:
    def acquire_token_for_client(self, scopes: list[str]) -> dict[str, Any]:
        del scopes
        return {"access_token": "tok", "expires_in": 3600}


def test_default_provider_get_pfx_bytes_is_none() -> None:
    class _P(CredentialProvider):
        def get_credentials(self, tenant_key: str = DEFAULT_TENANT_KEY) -> AzureCredentials:
            return _creds("/x.pfx")

    assert _P().get_pfx_bytes() is None


def test_load_pfx_rejects_garbage_without_leaking_source() -> None:
    with pytest.raises(AuthError) as exc_info:
        load_pfx(b"not a pfx", None)
    assert "invalid PFX" in str(exc_info.value)


def test_load_pfx_wrong_passphrase() -> None:
    with pytest.raises(AuthError):
        load_pfx(make_pfx("right"), "wrong")


def test_normalize_pfx_decrypts_once() -> None:
    encrypted = make_pfx("s3cret")
    plain = normalize_pfx(encrypted, "s3cret")
    load_pfx(plain, None)  # loads without a passphrase now
    unchanged = make_pfx()
    assert normalize_pfx(unchanged, None) == unchanged


def test_pfx_to_msal_credential_pem_shape() -> None:
    cred = pfx_to_msal_credential(make_pfx("pw"), "pw")
    assert cred["private_key"].startswith("-----BEGIN PRIVATE KEY-----")
    assert cred["public_certificate"].startswith("-----BEGIN CERTIFICATE-----")
    assert "passphrase" not in cred


class _FakeMsalResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.status_code = 200
        self.text = json.dumps(payload)
        self.headers: dict[str, str] = {}

    def raise_for_status(self) -> None:
        return None


class _FakeMsalHttp:
    """Minimal stand-in for MSAL's ``http_client`` — keeps the test offline."""

    def __init__(self) -> None:
        self.posts: list[dict[str, Any]] = []

    def get(self, url: str, **kwargs: Any) -> _FakeMsalResponse:
        del kwargs
        base = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111"
        assert "openid-configuration" in url
        return _FakeMsalResponse(
            {
                "authorization_endpoint": f"{base}/oauth2/v2.0/authorize",
                "token_endpoint": f"{base}/oauth2/v2.0/token",
                "issuer": f"{base}/v2.0",
            }
        )

    def post(self, url: str, data: Any = None, **kwargs: Any) -> _FakeMsalResponse:
        del url, kwargs
        self.posts.append(dict(data or {}))
        return _FakeMsalResponse(
            {"access_token": "tok", "expires_in": 3600, "token_type": "Bearer"}
        )

    def close(self) -> None:
        return None


def test_pfx_credential_is_accepted_by_real_msal() -> None:
    """End-to-end through real MSAL: the PEM credential signs a client assertion."""
    import base64

    cred = pfx_to_msal_credential(make_pfx("pw"), "pw")
    http = _FakeMsalHttp()
    app = msal.ConfidentialClientApplication(
        client_id="22222222-2222-2222-2222-222222222222",
        authority="https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111",
        client_credential=cred,
        http_client=http,
        instance_discovery=False,
    )
    result = app.acquire_token_for_client(scopes=["https://api.loganalytics.io/.default"])
    assert result["access_token"] == "tok"
    assertion = http.posts[-1]["client_assertion"]
    if isinstance(assertion, bytes):
        assertion = assertion.decode("ascii")
    header_b64 = assertion.split(".")[0]
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
    assert "x5t#S256" in header or "x5t" in header


def test_build_client_credential_prefers_bytes() -> None:
    cred = _build_client_credential(_creds("/ignored.pfx"), make_pfx())
    assert "private_key" in cred
    assert "private_key_pfx_path" not in cred


def test_build_client_credential_without_any_source() -> None:
    with pytest.raises(AuthError, match="No certificate source"):
        _build_client_credential(_creds(None))


def test_token_manager_uses_pfx_bytes_and_rebuilds_on_rotation() -> None:
    clock = [1000.0]
    provider = _BytesProvider(make_pfx())
    factory = _RecordingFactory()
    manager = TokenManager(provider, msal_factory=factory, time_source=lambda: clock[0])

    manager.get_token()
    assert len(factory.credentials) == 1
    assert "private_key" in factory.credentials[0]

    # Token refresh with same bytes reuses the MSAL app.
    clock[0] += 4000
    manager.get_token()
    assert len(factory.credentials) == 1

    # Rotated certificate -> new MSAL app.
    provider.pfx = make_pfx()
    clock[0] += 4000
    manager.get_token()
    assert len(factory.credentials) == 2


class _CountingSource(PfxSource):
    store = "test"

    def __init__(self, results: list[bytes | Exception]) -> None:
        self.results = results
        self.calls = 0

    def fetch_pfx(self) -> bytes:
        item = self.results[min(self.calls, len(self.results) - 1)]
        self.calls += 1
        if isinstance(item, Exception):
            raise item
        return item


def test_caching_source_respects_ttl() -> None:
    clock = [0.0]
    src = _CountingSource([b"a", b"b"])
    cache = CachingPfxSource(src, tenant_key="t", ttl_seconds=10, time_source=lambda: clock[0])
    assert cache.get() == b"a"
    clock[0] = 5
    assert cache.get() == b"a"
    clock[0] = 11
    assert cache.get() == b"b"
    assert src.calls == 2
    assert cache.source is src


def test_caching_source_wraps_unexpected_errors() -> None:
    cache = CachingPfxSource(_CountingSource([RuntimeError("boom /secret/path")]), tenant_key="t")
    with pytest.raises(AuthError) as exc_info:
        cache.get()
    assert "/secret/path" not in str(exc_info.value)


def test_caching_source_passes_auth_errors_through() -> None:
    cache = CachingPfxSource(_CountingSource([AuthError("nope")]), tenant_key="t")
    with pytest.raises(AuthError, match="nope"):
        cache.get()


def test_caching_source_wraps_upstream_errors() -> None:
    cache = CachingPfxSource(_CountingSource([UpstreamError("x")]), tenant_key="t")
    with pytest.raises(AuthError, match="secret store"):
        cache.get()


def _write_config(tmp_path: Path, data: dict[str, Any]) -> Path:
    path = tmp_path / "tenants.json"
    path.write_text(json.dumps(data))
    os.chmod(path, 0o600)
    return path


def test_json_provider_requires_a_certificate_source(tmp_path: Path) -> None:
    path = _write_config(
        tmp_path,
        {
            "default": "a",
            "tenants": {"a": {"tenant_id": "t", "client_id": "c", "workspace_id": _GUID}},
        },
    )
    with pytest.raises(AuthError, match="exactly one certificate source"):
        JsonFileCredentialProvider(path, env={})


def test_json_provider_file_tenant_has_no_pfx_bytes(tmp_path: Path) -> None:
    pfx = tmp_path / "c.pfx"
    pfx.write_bytes(b"x")
    path = _write_config(
        tmp_path,
        {
            "default": "a",
            "tenants": {
                "a": {
                    "tenant_id": "t",
                    "client_id": "c",
                    "cert_path": str(pfx),
                    "workspace_id": _GUID,
                }
            },
        },
    )
    provider = JsonFileCredentialProvider(path, env={})
    assert provider.get_pfx_bytes() is None
    assert provider.get_pfx_bytes("a") is None
    with pytest.raises(AuthError, match="Unknown tenant"):
        provider.get_pfx_bytes("nope")


def test_lazy_provider_delegates_pfx_bytes_to_token_manager() -> None:
    """Production wraps every provider in LazyCredentialProvider; the PFX-bytes
    path must survive that wrapper or secret-store tenants silently break."""
    from mcp_sentinel_detection_engine.auth import LazyCredentialProvider

    pfx = make_pfx()
    inner = _BytesProvider(pfx)
    lazy = LazyCredentialProvider(lambda: inner)
    assert lazy.get_pfx_bytes() == pfx

    factory = _RecordingFactory()
    manager = TokenManager(lazy, msal_factory=factory)
    assert manager.get_token() == "tok"
    assert inner.pfx_calls >= 1
    assert "private_key" in factory.credentials[0]
    assert "private_key_pfx_path" not in factory.credentials[0]


def test_lazy_provider_pfx_bytes_surfaces_auth_error() -> None:
    from mcp_sentinel_detection_engine.auth import LazyCredentialProvider

    def unconfigured() -> CredentialProvider:
        raise AuthError("Missing required Azure credential environment variables")

    with pytest.raises(AuthError):
        LazyCredentialProvider(unconfigured).get_pfx_bytes()
