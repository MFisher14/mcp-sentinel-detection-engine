"""Azure authentication and token management for the Log Analytics data plane."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import msal

from .audit import audit
from .errors import AuthError

DEFAULT_LOGANALYTICS_RESOURCE = "https://api.loganalytics.io"
DEFAULT_LOGANALYTICS_SCOPE = f"{DEFAULT_LOGANALYTICS_RESOURCE}/.default"

DEFAULT_TENANT_KEY = "default"

_REFRESH_LEEWAY_SECONDS = 60

_TENANT_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


@dataclass(frozen=True)
class AzureCredentials:
    """Identity material for an Azure App Registration plus the bound Sentinel workspace."""

    tenant_id: str
    client_id: str
    cert_path: str
    workspace_id: str
    cert_passphrase: str | None = None

    def __repr__(self) -> str:
        passphrase_repr = "None" if self.cert_passphrase is None else "'***REDACTED***'"
        return (
            f"AzureCredentials(tenant_id={self.tenant_id!r}, "
            f"client_id={self.client_id!r}, cert_path={self.cert_path!r}, "
            f"workspace_id={self.workspace_id!r}, "
            f"cert_passphrase={passphrase_repr})"
        )

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"


class CredentialProvider(ABC):
    """Returns Azure credentials for a given logical tenant key."""

    @abstractmethod
    def get_credentials(self, tenant_key: str = DEFAULT_TENANT_KEY) -> AzureCredentials: ...

    def list_tenants(self) -> list[str]:
        return [DEFAULT_TENANT_KEY]

    @property
    def default_tenant_key(self) -> str:
        return DEFAULT_TENANT_KEY


def _require_pfx_readable(path: str, *, source: str) -> None:
    pfx = Path(path)
    if not pfx.is_file():
        raise AuthError(f"Certificate file not found ({source}): {path}")
    if not os.access(pfx, os.R_OK):
        raise AuthError(f"Certificate file not readable ({source}): {path}")


def _validate_workspace_id(value: str, *, source: str) -> str:
    cleaned = value.strip()
    if not _GUID_RE.match(cleaned):
        raise AuthError(f"workspace_id must be a GUID ({source})")
    return cleaned


class EnvCredentialProvider(CredentialProvider):
    """Loads a single tenant's credentials from process environment variables."""

    REQUIRED_VARS = (
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CERT_PATH",
        "SENTINEL_WORKSPACE_ID",
    )
    PASSPHRASE_VAR = "AZURE_CERT_PASSPHRASE"  # noqa: S105

    def __init__(self, env: dict[str, str] | None = None) -> None:
        source: dict[str, str] = dict(env) if env is not None else dict(os.environ)
        missing = [name for name in self.REQUIRED_VARS if not source.get(name)]
        if missing:
            raise AuthError(
                "Missing required Azure credential environment variables: "
                + ", ".join(missing)
                + ". See .env.example for setup."
            )
        cert_path = source["AZURE_CERT_PATH"].strip()
        _require_pfx_readable(cert_path, source="AZURE_CERT_PATH")
        workspace_id = _validate_workspace_id(
            source["SENTINEL_WORKSPACE_ID"], source="SENTINEL_WORKSPACE_ID"
        )
        passphrase = source.get(self.PASSPHRASE_VAR) or None
        self._credentials = AzureCredentials(
            tenant_id=source["AZURE_TENANT_ID"].strip(),
            client_id=source["AZURE_CLIENT_ID"].strip(),
            cert_path=cert_path,
            workspace_id=workspace_id,
            cert_passphrase=passphrase,
        )

    def get_credentials(self, tenant_key: str = DEFAULT_TENANT_KEY) -> AzureCredentials:
        if tenant_key != DEFAULT_TENANT_KEY:
            raise AuthError("Unknown tenant")
        return self._credentials


class JsonFileCredentialProvider(CredentialProvider):
    """Loads N tenant credential bundles from a JSON config file."""

    def __init__(self, path: str | Path, *, env: dict[str, str] | None = None) -> None:
        self._path = Path(path)
        env_source: dict[str, str] = dict(env) if env is not None else dict(os.environ)
        if not self._path.is_file():
            raise AuthError(f"Tenants config file not found: {self._path}")
        self._check_permissions(self._path)
        try:
            raw = self._path.read_text(encoding="utf-8")
        except OSError as exc:
            raise AuthError(f"Failed to read tenants config: {self._path}") from exc
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AuthError(f"Tenants config is not valid JSON: {self._path}") from exc

        self._default_tenant, self._tenants = self._parse(data, env_source)

    @staticmethod
    def _check_permissions(path: Path) -> None:
        if sys.platform.startswith("win"):
            return
        try:
            mode = path.stat().st_mode
        except OSError as exc:
            raise AuthError(f"Failed to stat tenants config: {path}") from exc
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise AuthError(
                f"Tenants config file permissions are too permissive (need 0600): {path}"
            )

    @staticmethod
    def _parse(data: Any, env_source: dict[str, str]) -> tuple[str, dict[str, AzureCredentials]]:
        if not isinstance(data, dict):
            raise AuthError("Tenants config root must be a JSON object")
        tenants_raw = data.get("tenants")
        if not isinstance(tenants_raw, dict) or not tenants_raw:
            raise AuthError("Tenants config must contain a non-empty 'tenants' object")

        parsed: dict[str, AzureCredentials] = {}
        for key, entry in tenants_raw.items():
            if not isinstance(key, str) or not _TENANT_KEY_RE.match(key):
                raise AuthError(
                    "Invalid tenant key in tenants config (must match [A-Za-z0-9_-]{1,64})"
                )
            if not isinstance(entry, dict):
                raise AuthError(f"Tenant entry must be an object: '{key}'")
            tenant_id = entry.get("tenant_id")
            client_id = entry.get("client_id")
            cert_path = entry.get("cert_path")
            workspace_id_raw = entry.get("workspace_id")
            if not (
                isinstance(tenant_id, str)
                and isinstance(client_id, str)
                and isinstance(cert_path, str)
                and isinstance(workspace_id_raw, str)
            ):
                raise AuthError(
                    f"Tenant '{key}' missing required string fields "
                    "(tenant_id, client_id, cert_path, workspace_id)"
                )
            _require_pfx_readable(cert_path, source=f"tenant '{key}'")
            workspace_id = _validate_workspace_id(workspace_id_raw, source=f"tenant '{key}'")
            passphrase = JsonFileCredentialProvider._resolve_passphrase(key, entry, env_source)
            parsed[key] = AzureCredentials(
                tenant_id=tenant_id.strip(),
                client_id=client_id.strip(),
                cert_path=cert_path,
                workspace_id=workspace_id,
                cert_passphrase=passphrase,
            )

        default_key = data.get("default")
        if not isinstance(default_key, str) or default_key not in parsed:
            raise AuthError("Tenants config 'default' must name an existing tenant key")
        return default_key, parsed

    @staticmethod
    def _resolve_passphrase(
        tenant_key: str, entry: dict[str, Any], env_source: dict[str, str]
    ) -> str | None:
        env_name = entry.get("cert_passphrase_env")
        inline = entry.get("cert_passphrase")
        if env_name is not None and inline is not None:
            raise AuthError(
                f"Tenant '{tenant_key}' specifies both cert_passphrase_env and "
                "cert_passphrase; choose one."
            )
        if isinstance(env_name, str) and env_name:
            value = env_source.get(env_name)
            if not value:
                raise AuthError(
                    f"Tenant '{tenant_key}' cert_passphrase_env '{env_name}' "
                    "is not set in the environment"
                )
            return value
        if isinstance(inline, str) and inline:
            audit(
                "tenants-config-inline-passphrase",
                tenant=tenant_key,
                advice="prefer cert_passphrase_env to keep secrets out of config files",
            )
            return inline
        return None

    def get_credentials(self, tenant_key: str = DEFAULT_TENANT_KEY) -> AzureCredentials:
        resolved = self._default_tenant if tenant_key == DEFAULT_TENANT_KEY else tenant_key
        creds = self._tenants.get(resolved)
        if creds is None:
            raise AuthError("Unknown tenant")
        return creds

    def list_tenants(self) -> list[str]:
        return sorted(self._tenants.keys())

    @property
    def default_tenant_key(self) -> str:
        return self._default_tenant


class _MsalAppFactory(Protocol):
    def __call__(
        self,
        *,
        client_id: str,
        authority: str,
        client_credential: dict[str, Any],
    ) -> msal.ConfidentialClientApplication: ...


def _default_msal_factory(
    *,
    client_id: str,
    authority: str,
    client_credential: dict[str, Any],
) -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        client_id=client_id,
        authority=authority,
        client_credential=client_credential,
    )


def _build_client_credential(creds: AzureCredentials) -> dict[str, Any]:
    payload: dict[str, Any] = {"private_key_pfx_path": creds.cert_path}
    if creds.cert_passphrase is not None:
        payload["passphrase"] = creds.cert_passphrase
    return payload


@dataclass
class _CachedToken:
    access_token: str
    expires_at_epoch: float

    def is_fresh(self, now: float, leeway: float = _REFRESH_LEEWAY_SECONDS) -> bool:
        return self.expires_at_epoch - leeway > now


class TokenManager:
    """Acquires and caches access tokens for the Log Analytics query API."""

    def __init__(
        self,
        credential_provider: CredentialProvider,
        *,
        scope: str = DEFAULT_LOGANALYTICS_SCOPE,
        msal_factory: _MsalAppFactory | None = None,
        time_source: Callable[[], float] | None = None,
    ) -> None:
        self._credential_provider = credential_provider
        self._scope = scope
        self._msal_factory = msal_factory or _default_msal_factory
        self._time_source: Callable[[], float] = time_source or time.time
        self._cache: dict[tuple[str, str], _CachedToken] = {}
        self._apps: dict[str, msal.ConfidentialClientApplication] = {}
        self._lock = threading.Lock()

    @property
    def scope(self) -> str:
        return self._scope

    @property
    def default_tenant_key(self) -> str:
        return self._credential_provider.default_tenant_key

    def list_tenants(self) -> list[str]:
        return self._credential_provider.list_tenants()

    def get_credentials(self, tenant_key: str = DEFAULT_TENANT_KEY) -> AzureCredentials:
        return self._credential_provider.get_credentials(tenant_key)

    def get_token(self, tenant_key: str = DEFAULT_TENANT_KEY) -> str:
        cache_key = (tenant_key, self._scope)
        now = self._time_source()
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached is not None and cached.is_fresh(now):
                return cached.access_token
            new_token = self._acquire(tenant_key)
            self._cache[cache_key] = new_token
            return new_token.access_token

    def invalidate(self, tenant_key: str = DEFAULT_TENANT_KEY) -> None:
        with self._lock:
            self._cache.pop((tenant_key, self._scope), None)

    def _acquire(self, tenant_key: str) -> _CachedToken:
        credentials = self._credential_provider.get_credentials(tenant_key)
        app = self._apps.get(tenant_key)
        if app is None:
            app = self._msal_factory(
                client_id=credentials.client_id,
                authority=credentials.authority,
                client_credential=_build_client_credential(credentials),
            )
            self._apps[tenant_key] = app

        result = app.acquire_token_for_client(scopes=[self._scope])

        if not isinstance(result, dict) or "access_token" not in result:
            error_code = result.get("error") if isinstance(result, dict) else "unknown_error"
            raise AuthError(f"Failed to acquire Azure access token: {error_code}")

        access_token = str(result["access_token"])
        expires_in = float(result.get("expires_in", 3300))
        expires_at = self._time_source() + expires_in
        return _CachedToken(access_token=access_token, expires_at_epoch=expires_at)


def build_default_token_manager() -> TokenManager:
    """Build the token manager used by the production server."""
    tenants_file = os.environ.get("MCP_SENTINEL_TENANTS_FILE")
    provider: CredentialProvider
    if tenants_file:
        provider = JsonFileCredentialProvider(tenants_file)
    else:
        provider = EnvCredentialProvider()
    return TokenManager(provider)
