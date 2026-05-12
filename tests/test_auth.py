"""Tests for the auth module."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from mcp_sentinel_detection_engine.auth import (
    AzureCredentials,
    EnvCredentialProvider,
    JsonFileCredentialProvider,
    TokenManager,
    _build_client_credential,
)
from mcp_sentinel_detection_engine.errors import AuthError

_VALID_GUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
_OTHER_GUID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


# ---------- AzureCredentials ----------


def test_credentials_repr_redacts_passphrase() -> None:
    creds = AzureCredentials(
        tenant_id="t",
        client_id="c",
        cert_path="/p/cert.pfx",
        workspace_id=_VALID_GUID,
        cert_passphrase="super-secret",
    )
    rendered = repr(creds)
    assert "super-secret" not in rendered
    assert "REDACTED" in rendered
    assert "/p/cert.pfx" in rendered


def test_credentials_repr_when_no_passphrase() -> None:
    creds = AzureCredentials(
        tenant_id="t", client_id="c", cert_path="/p/cert.pfx", workspace_id=_VALID_GUID
    )
    rendered = repr(creds)
    assert "REDACTED" not in rendered
    assert "None" in rendered
    assert _VALID_GUID in rendered


def test_credentials_authority_url() -> None:
    creds = AzureCredentials(
        tenant_id="abc", client_id="c", cert_path="/p/c.pfx", workspace_id=_VALID_GUID
    )
    assert creds.authority == "https://login.microsoftonline.com/abc"


def test_build_client_credential_with_passphrase(tmp_path: Path) -> None:
    pfx = tmp_path / "c.pfx"
    pfx.write_bytes(b"\x00")
    creds = AzureCredentials(
        tenant_id="t",
        client_id="c",
        cert_path=str(pfx),
        workspace_id=_VALID_GUID,
        cert_passphrase="pw",
    )
    cc = _build_client_credential(creds)
    assert cc == {"private_key_pfx_path": str(pfx), "passphrase": "pw"}


def test_build_client_credential_without_passphrase(tmp_path: Path) -> None:
    pfx = tmp_path / "c.pfx"
    pfx.write_bytes(b"\x00")
    creds = AzureCredentials(
        tenant_id="t", client_id="c", cert_path=str(pfx), workspace_id=_VALID_GUID
    )
    cc = _build_client_credential(creds)
    assert "passphrase" not in cc
    assert cc["private_key_pfx_path"] == str(pfx)


# ---------- EnvCredentialProvider ----------


def _base_env(pfx: Path) -> dict[str, str]:
    return {
        "AZURE_TENANT_ID": "tenant-abc",
        "AZURE_CLIENT_ID": "client-xyz",
        "AZURE_CERT_PATH": str(pfx),
        "SENTINEL_WORKSPACE_ID": _VALID_GUID,
    }


def test_env_provider_loads_credentials(tmp_path: Path) -> None:
    pfx = tmp_path / "app.pfx"
    pfx.write_bytes(b"\x00")
    env = {**_base_env(pfx), "AZURE_CERT_PASSPHRASE": "pw"}
    provider = EnvCredentialProvider(env)
    creds = provider.get_credentials()
    assert creds.tenant_id == "tenant-abc"
    assert creds.client_id == "client-xyz"
    assert creds.cert_path == str(pfx)
    assert creds.workspace_id == _VALID_GUID
    assert creds.cert_passphrase == "pw"
    assert "pw" not in repr(creds)


def test_env_provider_passphrase_optional(tmp_path: Path) -> None:
    pfx = tmp_path / "app.pfx"
    pfx.write_bytes(b"\x00")
    creds = EnvCredentialProvider(_base_env(pfx)).get_credentials()
    assert creds.cert_passphrase is None


@pytest.mark.parametrize(
    "missing",
    ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CERT_PATH", "SENTINEL_WORKSPACE_ID"],
)
def test_env_provider_missing_var_fails_fast(missing: str, tmp_path: Path) -> None:
    pfx = tmp_path / "app.pfx"
    pfx.write_bytes(b"\x00")
    env = _base_env(pfx)
    del env[missing]
    with pytest.raises(AuthError) as exc_info:
        EnvCredentialProvider(env)
    assert missing in str(exc_info.value)


def test_env_provider_missing_cert_file_fails_fast() -> None:
    env = {
        "AZURE_TENANT_ID": "t",
        "AZURE_CLIENT_ID": "c",
        "AZURE_CERT_PATH": "/nonexistent/cert.pfx",
        "SENTINEL_WORKSPACE_ID": _VALID_GUID,
    }
    with pytest.raises(AuthError) as exc_info:
        EnvCredentialProvider(env)
    assert "Certificate file not found" in str(exc_info.value)
    assert "AZURE_CERT_PATH" in str(exc_info.value)


def test_env_provider_rejects_non_guid_workspace(tmp_path: Path) -> None:
    pfx = tmp_path / "app.pfx"
    pfx.write_bytes(b"\x00")
    env = _base_env(pfx)
    env["SENTINEL_WORKSPACE_ID"] = "not-a-guid"
    with pytest.raises(AuthError) as exc_info:
        EnvCredentialProvider(env)
    assert "workspace_id" in str(exc_info.value)


def test_env_provider_rejects_non_default_tenant_key(tmp_path: Path) -> None:
    pfx = tmp_path / "app.pfx"
    pfx.write_bytes(b"\x00")
    provider = EnvCredentialProvider(_base_env(pfx))
    with pytest.raises(AuthError):
        provider.get_credentials("contoso")


def test_env_provider_list_tenants_is_default(tmp_path: Path) -> None:
    pfx = tmp_path / "app.pfx"
    pfx.write_bytes(b"\x00")
    provider = EnvCredentialProvider(_base_env(pfx))
    assert provider.list_tenants() == ["default"]
    assert provider.default_tenant_key == "default"


# ---------- JsonFileCredentialProvider ----------


def _write_tenants_file(path: Path, payload: dict[str, Any], *, mode: int = 0o600) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(path, mode)
    return path


def test_json_provider_happy_path(tmp_path: Path) -> None:
    pfx_a = tmp_path / "a.pfx"
    pfx_a.write_bytes(b"\x00")
    pfx_b = tmp_path / "b.pfx"
    pfx_b.write_bytes(b"\x00")
    cfg = _write_tenants_file(
        tmp_path / "tenants.json",
        {
            "default": "contoso",
            "tenants": {
                "contoso": {
                    "tenant_id": "11111111-1111-1111-1111-111111111111",
                    "client_id": "22222222-2222-2222-2222-222222222222",
                    "cert_path": str(pfx_a),
                    "workspace_id": _VALID_GUID,
                },
                "fabrikam": {
                    "tenant_id": "33333333-3333-3333-3333-333333333333",
                    "client_id": "44444444-4444-4444-4444-444444444444",
                    "cert_path": str(pfx_b),
                    "workspace_id": _OTHER_GUID,
                },
            },
        },
    )
    provider = JsonFileCredentialProvider(cfg, env={})
    assert provider.list_tenants() == ["contoso", "fabrikam"]
    assert provider.default_tenant_key == "contoso"
    contoso = provider.get_credentials("contoso")
    assert contoso.cert_path == str(pfx_a)
    assert contoso.workspace_id == _VALID_GUID
    assert contoso.cert_passphrase is None
    fabrikam = provider.get_credentials("fabrikam")
    assert fabrikam.workspace_id == _OTHER_GUID
    assert provider.get_credentials("default").tenant_id == contoso.tenant_id


def test_json_provider_requires_workspace_id(tmp_path: Path) -> None:
    pfx = tmp_path / "a.pfx"
    pfx.write_bytes(b"\x00")
    cfg = _write_tenants_file(
        tmp_path / "tenants.json",
        {
            "default": "contoso",
            "tenants": {
                "contoso": {
                    "tenant_id": "t",
                    "client_id": "c",
                    "cert_path": str(pfx),
                }
            },
        },
    )
    with pytest.raises(AuthError) as exc_info:
        JsonFileCredentialProvider(cfg, env={})
    assert "workspace_id" in str(exc_info.value)


def test_json_provider_rejects_non_guid_workspace(tmp_path: Path) -> None:
    pfx = tmp_path / "a.pfx"
    pfx.write_bytes(b"\x00")
    cfg = _write_tenants_file(
        tmp_path / "tenants.json",
        {
            "default": "contoso",
            "tenants": {
                "contoso": {
                    "tenant_id": "t",
                    "client_id": "c",
                    "cert_path": str(pfx),
                    "workspace_id": "not-a-guid",
                }
            },
        },
    )
    with pytest.raises(AuthError) as exc_info:
        JsonFileCredentialProvider(cfg, env={})
    assert "workspace_id" in str(exc_info.value)


def test_json_provider_unknown_tenant_does_not_echo_key(tmp_path: Path) -> None:
    pfx = tmp_path / "a.pfx"
    pfx.write_bytes(b"\x00")
    cfg = _write_tenants_file(
        tmp_path / "tenants.json",
        {
            "default": "contoso",
            "tenants": {
                "contoso": {
                    "tenant_id": "t",
                    "client_id": "c",
                    "cert_path": str(pfx),
                    "workspace_id": _VALID_GUID,
                }
            },
        },
    )
    provider = JsonFileCredentialProvider(cfg, env={})
    with pytest.raises(AuthError) as exc_info:
        provider.get_credentials("attacker-controlled-key")
    assert "attacker-controlled-key" not in str(exc_info.value)


def test_json_provider_resolves_passphrase_from_env(tmp_path: Path) -> None:
    pfx = tmp_path / "a.pfx"
    pfx.write_bytes(b"\x00")
    cfg = _write_tenants_file(
        tmp_path / "tenants.json",
        {
            "default": "contoso",
            "tenants": {
                "contoso": {
                    "tenant_id": "t",
                    "client_id": "c",
                    "cert_path": str(pfx),
                    "workspace_id": _VALID_GUID,
                    "cert_passphrase_env": "CONTOSO_PW",
                }
            },
        },
    )
    provider = JsonFileCredentialProvider(cfg, env={"CONTOSO_PW": "hunter2"})
    assert provider.get_credentials("contoso").cert_passphrase == "hunter2"


def test_json_provider_passphrase_env_missing(tmp_path: Path) -> None:
    pfx = tmp_path / "a.pfx"
    pfx.write_bytes(b"\x00")
    cfg = _write_tenants_file(
        tmp_path / "tenants.json",
        {
            "default": "contoso",
            "tenants": {
                "contoso": {
                    "tenant_id": "t",
                    "client_id": "c",
                    "cert_path": str(pfx),
                    "workspace_id": _VALID_GUID,
                    "cert_passphrase_env": "MISSING_PW",
                }
            },
        },
    )
    with pytest.raises(AuthError) as exc_info:
        JsonFileCredentialProvider(cfg, env={})
    assert "MISSING_PW" in str(exc_info.value)


def test_json_provider_rejects_both_passphrase_forms(tmp_path: Path) -> None:
    pfx = tmp_path / "a.pfx"
    pfx.write_bytes(b"\x00")
    cfg = _write_tenants_file(
        tmp_path / "tenants.json",
        {
            "default": "contoso",
            "tenants": {
                "contoso": {
                    "tenant_id": "t",
                    "client_id": "c",
                    "cert_path": str(pfx),
                    "workspace_id": _VALID_GUID,
                    "cert_passphrase": "inline",
                    "cert_passphrase_env": "X",
                }
            },
        },
    )
    with pytest.raises(AuthError) as exc_info:
        JsonFileCredentialProvider(cfg, env={"X": "y"})
    assert "choose one" in str(exc_info.value)


def test_json_provider_inline_passphrase_works(tmp_path: Path) -> None:
    pfx = tmp_path / "a.pfx"
    pfx.write_bytes(b"\x00")
    cfg = _write_tenants_file(
        tmp_path / "tenants.json",
        {
            "default": "contoso",
            "tenants": {
                "contoso": {
                    "tenant_id": "t",
                    "client_id": "c",
                    "cert_path": str(pfx),
                    "workspace_id": _VALID_GUID,
                    "cert_passphrase": "inline",
                }
            },
        },
    )
    provider = JsonFileCredentialProvider(cfg, env={})
    assert provider.get_credentials("contoso").cert_passphrase == "inline"


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX perms only")
def test_json_provider_rejects_world_readable_file(tmp_path: Path) -> None:
    pfx = tmp_path / "a.pfx"
    pfx.write_bytes(b"\x00")
    cfg = _write_tenants_file(
        tmp_path / "tenants.json",
        {
            "default": "contoso",
            "tenants": {
                "contoso": {
                    "tenant_id": "t",
                    "client_id": "c",
                    "cert_path": str(pfx),
                    "workspace_id": _VALID_GUID,
                }
            },
        },
        mode=0o644,
    )
    with pytest.raises(AuthError) as exc_info:
        JsonFileCredentialProvider(cfg, env={})
    assert "permissions are too permissive" in str(exc_info.value)
    os.chmod(cfg, stat.S_IRUSR | stat.S_IWUSR)
    JsonFileCredentialProvider(cfg, env={})


def test_json_provider_missing_default(tmp_path: Path) -> None:
    pfx = tmp_path / "a.pfx"
    pfx.write_bytes(b"\x00")
    cfg = _write_tenants_file(
        tmp_path / "tenants.json",
        {
            "default": "missing",
            "tenants": {
                "contoso": {
                    "tenant_id": "t",
                    "client_id": "c",
                    "cert_path": str(pfx),
                    "workspace_id": _VALID_GUID,
                }
            },
        },
    )
    with pytest.raises(AuthError):
        JsonFileCredentialProvider(cfg, env={})


def test_json_provider_invalid_tenant_key(tmp_path: Path) -> None:
    pfx = tmp_path / "a.pfx"
    pfx.write_bytes(b"\x00")
    cfg = _write_tenants_file(
        tmp_path / "tenants.json",
        {
            "default": "bad key",
            "tenants": {
                "bad key": {
                    "tenant_id": "t",
                    "client_id": "c",
                    "cert_path": str(pfx),
                    "workspace_id": _VALID_GUID,
                }
            },
        },
    )
    with pytest.raises(AuthError) as exc_info:
        JsonFileCredentialProvider(cfg, env={})
    assert "tenant key" in str(exc_info.value).lower()


def test_json_provider_cert_file_must_exist(tmp_path: Path) -> None:
    cfg = _write_tenants_file(
        tmp_path / "tenants.json",
        {
            "default": "contoso",
            "tenants": {
                "contoso": {
                    "tenant_id": "t",
                    "client_id": "c",
                    "cert_path": "/nonexistent.pfx",
                    "workspace_id": _VALID_GUID,
                }
            },
        },
    )
    with pytest.raises(AuthError) as exc_info:
        JsonFileCredentialProvider(cfg, env={})
    assert "Certificate file not found" in str(exc_info.value)


def test_json_provider_missing_file() -> None:
    with pytest.raises(AuthError) as exc_info:
        JsonFileCredentialProvider("/nonexistent.json", env={})
    assert "not found" in str(exc_info.value)


def test_json_provider_invalid_json(tmp_path: Path) -> None:
    cfg = tmp_path / "tenants.json"
    cfg.write_text("not json", encoding="utf-8")
    os.chmod(cfg, 0o600)
    with pytest.raises(AuthError) as exc_info:
        JsonFileCredentialProvider(cfg, env={})
    assert "valid JSON" in str(exc_info.value)


# ---------- TokenManager ----------


def test_token_manager_caches_token(fake_provider, fake_msal_app) -> None:
    fake_msal_app.results = [
        {"access_token": "first", "expires_in": 3600},
        {"access_token": "second", "expires_in": 3600},
    ]
    times = iter([1000.0, 1010.0, 1020.0, 1030.0])
    manager = TokenManager(
        fake_provider,
        msal_factory=lambda **_: fake_msal_app,
        time_source=lambda: next(times),
    )
    assert manager.get_token() == "first"
    assert manager.get_token() == "first"
    assert fake_msal_app.calls == 1


def test_token_manager_refreshes_near_expiry(fake_provider, fake_msal_app) -> None:
    fake_msal_app.results = [
        {"access_token": "first", "expires_in": 60},
        {"access_token": "second", "expires_in": 3600},
    ]
    times = iter([1000.0, 1000.0, 2000.0, 2000.0])
    manager = TokenManager(
        fake_provider,
        msal_factory=lambda **_: fake_msal_app,
        time_source=lambda: next(times),
    )
    assert manager.get_token() == "first"
    assert manager.get_token() == "second"
    assert fake_msal_app.calls == 2


def test_token_manager_invalidate_forces_refresh(fake_provider, fake_msal_app) -> None:
    fake_msal_app.results = [
        {"access_token": "first", "expires_in": 3600},
        {"access_token": "second", "expires_in": 3600},
    ]
    manager = TokenManager(
        fake_provider,
        msal_factory=lambda **_: fake_msal_app,
        time_source=lambda: 1000.0,
    )
    assert manager.get_token() == "first"
    manager.invalidate()
    assert manager.get_token() == "second"
    assert fake_msal_app.calls == 2


def test_token_manager_msal_failure_raises_auth_error(fake_provider) -> None:
    class FailingApp:
        def acquire_token_for_client(self, scopes: list[str]) -> dict[str, Any]:
            del scopes
            return {"error": "invalid_client", "error_description": "Secret xyz invalid"}

    manager = TokenManager(
        fake_provider,
        msal_factory=lambda **_: FailingApp(),
    )
    with pytest.raises(AuthError) as exc:
        manager.get_token()
    assert "Secret xyz invalid" not in str(exc.value)
    assert "invalid_client" in str(exc.value)


def test_token_manager_passes_cert_dict_to_factory(fake_provider) -> None:
    captured: dict[str, Any] = {}

    class StubApp:
        def acquire_token_for_client(self, scopes: list[str]) -> dict[str, Any]:
            del scopes
            return {"access_token": "ok", "expires_in": 3600}

    def factory(*, client_id: str, authority: str, client_credential: Any) -> Any:
        captured["client_id"] = client_id
        captured["authority"] = authority
        captured["client_credential"] = client_credential
        return StubApp()

    manager = TokenManager(fake_provider, msal_factory=factory)
    manager.get_token()
    assert captured["client_credential"] == {"private_key_pfx_path": "/dev/null"}


def test_token_manager_targets_loganalytics_scope(fake_provider, fake_msal_app) -> None:
    """Default scope must be Log Analytics, not Defender or Graph."""
    manager = TokenManager(fake_provider, msal_factory=lambda **_: fake_msal_app)
    manager.get_token()
    assert manager.scope == "https://api.loganalytics.io/.default"


def test_token_manager_per_tenant_cache_isolation() -> None:
    """Two tenants must never share each other's cached tokens."""
    from mcp_sentinel_detection_engine.auth import CredentialProvider

    class TwoTenantProvider(CredentialProvider):
        def __init__(self) -> None:
            self._creds = {
                "a": AzureCredentials(
                    tenant_id="aaa",
                    client_id="ca",
                    cert_path="/dev/null",
                    workspace_id=_VALID_GUID,
                ),
                "b": AzureCredentials(
                    tenant_id="bbb",
                    client_id="cb",
                    cert_path="/dev/null",
                    workspace_id=_OTHER_GUID,
                ),
            }

        def get_credentials(self, tenant_key: str = "default") -> AzureCredentials:
            if tenant_key == "default":
                tenant_key = "a"
            return self._creds[tenant_key]

        def list_tenants(self) -> list[str]:
            return ["a", "b"]

        @property
        def default_tenant_key(self) -> str:
            return "a"

    class TaggingApp:
        def __init__(self, tag: str) -> None:
            self.tag = tag

        def acquire_token_for_client(self, scopes: list[str]) -> dict[str, Any]:
            del scopes
            return {"access_token": f"token-{self.tag}", "expires_in": 3600}

    def factory(*, client_id: str, **_: Any) -> Any:
        return TaggingApp(client_id)

    manager = TokenManager(TwoTenantProvider(), msal_factory=factory)
    assert manager.get_token("a") == "token-ca"
    assert manager.get_token("b") == "token-cb"
    assert manager.get_token("a") == "token-ca"
