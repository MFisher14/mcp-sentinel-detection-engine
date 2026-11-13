"""Azure authentication and token management for the Log Analytics data plane."""

from __future__ import annotations

import hashlib
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
from .credentials import CachingPfxSource, PfxSource, pfx_to_msal_credential
from .errors import AuthError
from .ratelimit import RateLimitConfig, parse_rate_limits

DEFAULT_LOGANALYTICS_RESOURCE = "https://api.loganalytics.io"
DEFAULT_LOGANALYTICS_SCOPE = f"{DEFAULT_LOGANALYTICS_RESOURCE}/.default"

DEFAULT_MANAGEMENT_RESOURCE = "https://management.azure.com"
DEFAULT_MANAGEMENT_SCOPE = f"{DEFAULT_MANAGEMENT_RESOURCE}/.default"

DEFAULT_TENANT_KEY = "default"

_REFRESH_LEEWAY_SECONDS = 60

_TENANT_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# Azure resource-group names: 1-90 chars of alphanumerics, '-', '_', '.', '(' and ')';
# may not end in a period.
_RESOURCE_GROUP_RE = re.compile(r"^[-\w.()]{0,89}[-\w()]$")
# Log Analytics workspace names: 4-63 chars, alphanumerics and '-', must start
# and end with an alphanumeric.
_WORKSPACE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{2,61}[A-Za-z0-9]$")


@dataclass(frozen=True)
class ManagementTarget:
    """Azure Resource Manager coordinates of a Sentinel-enabled workspace."""

    subscription_id: str
    resource_group: str
    workspace_name: str

    @property
    def workspace_resource_id(self) -> str:
        return (
            f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
        )


def _parse_management_target(
    subscription_id: object,
    resource_group: object,
    workspace_name: object,
    *,
    source: str,
) -> ManagementTarget | None:
    """Validate the optional management-plane trio; all-or-nothing."""
    values = (subscription_id, resource_group, workspace_name)
    if all(v is None or v == "" for v in values):
        return None
    if not all(isinstance(v, str) and v.strip() for v in values):
        raise AuthError(
            f"subscription_id, resource_group and workspace_name must all be set "
            f"together ({source})"
        )
    sub = str(subscription_id).strip()
    rg = str(resource_group).strip()
    ws = str(workspace_name).strip()
    if not _GUID_RE.match(sub):
        raise AuthError(f"subscription_id must be a GUID ({source})")
    if not _RESOURCE_GROUP_RE.match(rg):
        raise AuthError(f"resource_group is not a valid Azure resource group name ({source})")
    if not _WORKSPACE_NAME_RE.match(ws):
        raise AuthError(f"workspace_name is not a valid Log Analytics workspace name ({source})")
    return ManagementTarget(subscription_id=sub, resource_group=rg, workspace_name=ws)


@dataclass(frozen=True)
class AzureCredentials:
    """Identity material for an Azure App Registration plus the bound Sentinel workspace."""

    tenant_id: str
    client_id: str
    # ``None`` when the provider materializes the PFX from a secret store via
    # ``CredentialProvider.get_pfx_bytes`` instead of the filesystem.
    cert_path: str | None
    workspace_id: str
    cert_passphrase: str | None = None
    management: ManagementTarget | None = None

    def __repr__(self) -> str:
        passphrase_repr = "None" if self.cert_passphrase is None else "'***REDACTED***'"
        return (
            f"AzureCredentials(tenant_id={self.tenant_id!r}, "
            f"client_id={self.client_id!r}, cert_path={self.cert_path!r}, "
            f"workspace_id={self.workspace_id!r}, "
            f"cert_passphrase={passphrase_repr}, management={self.management!r})"
        )

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"


class CredentialProvider(ABC):
    """Returns Azure credentials for a given logical tenant key."""

    @abstractmethod
    def get_credentials(self, tenant_key: str = DEFAULT_TENANT_KEY) -> AzureCredentials: ...

    def get_pfx_bytes(self, tenant_key: str = DEFAULT_TENANT_KEY) -> bytes | None:
        """Return raw PFX bytes for ``tenant_key``, or ``None`` to use ``cert_path``.

        Filesystem-backed providers keep this default. Secret-store providers
        (Key Vault, HashiCorp Vault, ...) override it so the certificate never
        has to exist on the host filesystem. Returned bytes are an
        *unencrypted* PFX unless ``AzureCredentials.cert_passphrase`` is set.
        """
        del tenant_key
        return None

    def list_tenants(self) -> list[str]:
        return [DEFAULT_TENANT_KEY]

    @property
    def default_tenant_key(self) -> str:
        return DEFAULT_TENANT_KEY

    def rate_limit_configs(self) -> dict[str, RateLimitConfig]:
        """Per-tenant quota overrides; tenants not listed use the defaults."""
        return {}


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
    MANAGEMENT_VARS = (
        "SENTINEL_SUBSCRIPTION_ID",
        "SENTINEL_RESOURCE_GROUP",
        "SENTINEL_WORKSPACE_NAME",
    )

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
        management = _parse_management_target(
            *(source.get(name) for name in self.MANAGEMENT_VARS),
            source="SENTINEL_SUBSCRIPTION_ID / SENTINEL_RESOURCE_GROUP / SENTINEL_WORKSPACE_NAME",
        )
        self._credentials = AzureCredentials(
            tenant_id=source["AZURE_TENANT_ID"].strip(),
            client_id=source["AZURE_CLIENT_ID"].strip(),
            cert_path=cert_path,
            workspace_id=workspace_id,
            cert_passphrase=passphrase,
            management=management,
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

        self._default_tenant, self._tenants, self._sources = self._parse(data, env_source)
        self._rate_limits = parse_rate_limits(data["tenants"])

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
    def _parse(
        data: Any, env_source: dict[str, str]
    ) -> tuple[str, dict[str, AzureCredentials], dict[str, CachingPfxSource]]:
        if not isinstance(data, dict):
            raise AuthError("Tenants config root must be a JSON object")
        tenants_raw = data.get("tenants")
        if not isinstance(tenants_raw, dict) or not tenants_raw:
            raise AuthError("Tenants config must contain a non-empty 'tenants' object")

        parsed: dict[str, AzureCredentials] = {}
        sources: dict[str, CachingPfxSource] = {}
        for key, entry in tenants_raw.items():
            if not isinstance(key, str) or not _TENANT_KEY_RE.match(key):
                raise AuthError(
                    "Invalid tenant key in tenants config (must match [A-Za-z0-9_-]{1,64})"
                )
            if not isinstance(entry, dict):
                raise AuthError(f"Tenant entry must be an object: '{key}'")
            tenant_id = entry.get("tenant_id")
            client_id = entry.get("client_id")
            workspace_id_raw = entry.get("workspace_id")
            if not (
                isinstance(tenant_id, str)
                and isinstance(client_id, str)
                and isinstance(workspace_id_raw, str)
            ):
                raise AuthError(
                    f"Tenant '{key}' missing required string fields "
                    "(tenant_id, client_id, workspace_id)"
                )
            cert_path, source = _parse_certificate_source(key, entry, env_source)
            passphrase: str | None
            if source is not None:
                if "cert_passphrase" in entry or "cert_passphrase_env" in entry:
                    raise AuthError(
                        f"Tenant '{key}' uses a secret-store certificate; configure the "
                        "passphrase inside that block, not cert_passphrase(_env)."
                    )
                sources[key] = CachingPfxSource(source, tenant_key=key)
                passphrase = None
            else:
                passphrase = JsonFileCredentialProvider._resolve_passphrase(key, entry, env_source)
            workspace_id = _validate_workspace_id(workspace_id_raw, source=f"tenant '{key}'")
            management = _parse_management_target(
                entry.get("subscription_id"),
                entry.get("resource_group"),
                entry.get("workspace_name"),
                source=f"tenant '{key}'",
            )
            parsed[key] = AzureCredentials(
                tenant_id=tenant_id.strip(),
                client_id=client_id.strip(),
                cert_path=cert_path,
                workspace_id=workspace_id,
                cert_passphrase=passphrase,
                management=management,
            )

        default_key = data.get("default")
        if not isinstance(default_key, str) or default_key not in parsed:
            raise AuthError("Tenants config 'default' must name an existing tenant key")
        return default_key, parsed, sources

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

    def get_pfx_bytes(self, tenant_key: str = DEFAULT_TENANT_KEY) -> bytes | None:
        resolved = self._default_tenant if tenant_key == DEFAULT_TENANT_KEY else tenant_key
        if resolved not in self._tenants:
            raise AuthError("Unknown tenant")
        source = self._sources.get(resolved)
        return None if source is None else source.get()

    def list_tenants(self) -> list[str]:
        return sorted(self._tenants.keys())

    def rate_limit_configs(self) -> dict[str, RateLimitConfig]:
        return dict(self._rate_limits)

    @property
    def default_tenant_key(self) -> str:
        return self._default_tenant


# Per-tenant certificate-source blocks recognised in the tenants JSON, in
# addition to ``cert_path``. Each parser lives in ``credentials/``, validates
# its block at load time, and returns a *lazy* PfxSource — nothing is fetched
# until the first token acquisition, so a transient secret-store outage does
# not stop the server (or the offline tools) from booting.
_SecretStoreParser = Callable[[str, dict[str, Any], dict[str, str]], PfxSource]


def _secret_store_parsers() -> dict[str, _SecretStoreParser]:
    return {}


def _parse_certificate_source(
    tenant_key: str, entry: dict[str, Any], env_source: dict[str, str]
) -> tuple[str | None, PfxSource | None]:
    """Return ``(cert_path, secret_store_source)`` — exactly one is non-``None``."""
    parsers = _secret_store_parsers()
    kinds = ("cert_path", *parsers)
    present = [name for name in kinds if entry.get(name) is not None]
    if len(present) != 1:
        raise AuthError(
            f"Tenant '{tenant_key}' must specify exactly one certificate source "
            f"({', '.join(kinds)})"
        )
    kind = present[0]
    if kind == "cert_path":
        cert_path = entry["cert_path"]
        if not isinstance(cert_path, str):
            raise AuthError(f"Tenant '{tenant_key}' cert_path must be a string")
        _require_pfx_readable(cert_path, source=f"tenant '{tenant_key}'")
        return cert_path, None
    block = entry[kind]
    if not isinstance(block, dict):
        raise AuthError(f"Tenant '{tenant_key}' {kind} must be an object")
    return None, parsers[kind](tenant_key, block, env_source)


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


def _build_client_credential(
    creds: AzureCredentials, pfx_bytes: bytes | None = None
) -> dict[str, Any]:
    if pfx_bytes is not None:
        # MSAL only accepts a PFX by path; for in-memory bytes hand it the PEM
        # key + certificate instead (it derives the thumbprints itself).
        return pfx_to_msal_credential(pfx_bytes, creds.cert_passphrase)
    if creds.cert_path is None:
        raise AuthError("No certificate source is configured for this tenant")
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
        self._allowed_scopes = frozenset({scope, DEFAULT_MANAGEMENT_SCOPE})
        self._msal_factory = msal_factory or _default_msal_factory
        self._time_source: Callable[[], float] = time_source or time.time
        self._cache: dict[tuple[str, str], _CachedToken] = {}
        # tenant_key -> (certificate fingerprint, MSAL app). The fingerprint lets
        # a rotated secret-store certificate replace the cached app.
        self._apps: dict[str, tuple[str, msal.ConfidentialClientApplication]] = {}
        self._lock = threading.Lock()

    @property
    def scope(self) -> str:
        return self._scope

    @property
    def default_tenant_key(self) -> str:
        return self._credential_provider.default_tenant_key

    def list_tenants(self) -> list[str]:
        return self._credential_provider.list_tenants()

    def rate_limit_configs(self) -> dict[str, RateLimitConfig]:
        return self._credential_provider.rate_limit_configs()

    def get_credentials(self, tenant_key: str = DEFAULT_TENANT_KEY) -> AzureCredentials:
        return self._credential_provider.get_credentials(tenant_key)

    def get_token(self, tenant_key: str = DEFAULT_TENANT_KEY, *, scope: str | None = None) -> str:
        """Return a cached-or-fresh token for ``(tenant_key, scope)``.

        ``scope`` defaults to the manager's primary scope (Log Analytics). The
        only other scope the server requests is :data:`DEFAULT_MANAGEMENT_SCOPE`
        for the read-only Sentinel management-plane tools.
        """
        effective_scope = scope or self._scope
        if effective_scope not in self._allowed_scopes:
            raise AuthError("Requested OAuth scope is not permitted by this server")
        cache_key = (tenant_key, effective_scope)
        now = self._time_source()
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached is not None and cached.is_fresh(now):
                return cached.access_token
            new_token = self._acquire(tenant_key, effective_scope)
            self._cache[cache_key] = new_token
            return new_token.access_token

    def invalidate(self, tenant_key: str = DEFAULT_TENANT_KEY, *, scope: str | None = None) -> None:
        with self._lock:
            self._cache.pop((tenant_key, scope or self._scope), None)

    def _acquire(self, tenant_key: str, scope: str) -> _CachedToken:
        credentials = self._credential_provider.get_credentials(tenant_key)
        pfx_bytes = self._credential_provider.get_pfx_bytes(tenant_key)
        fingerprint = (
            hashlib.sha256(pfx_bytes).hexdigest()
            if pfx_bytes is not None
            else f"path:{credentials.cert_path}"
        )
        cached_app = self._apps.get(tenant_key)
        if cached_app is not None and cached_app[0] == fingerprint:
            app = cached_app[1]
        else:
            if cached_app is not None:
                audit("certificate-rotated", tenant=tenant_key)
            app = self._msal_factory(
                client_id=credentials.client_id,
                authority=credentials.authority,
                client_credential=_build_client_credential(credentials, pfx_bytes),
            )
            self._apps[tenant_key] = (fingerprint, app)

        result = app.acquire_token_for_client(scopes=[scope])

        if not isinstance(result, dict) or "access_token" not in result:
            error_code = result.get("error") if isinstance(result, dict) else "unknown_error"
            raise AuthError(f"Failed to acquire Azure access token: {error_code}")

        access_token = str(result["access_token"])
        expires_in = float(result.get("expires_in", 3300))
        expires_at = self._time_source() + expires_in
        return _CachedToken(access_token=access_token, expires_at_epoch=expires_at)


class LazyCredentialProvider(CredentialProvider):
    """Defers building the real provider until a credential is actually needed.

    Three of the four tools (``convert_sigma_to_kql``,
    ``validate_kql_against_schema``, ``generate_sentinel_terraform``) are pure
    functions that never touch Azure. Constructing the credential provider
    eagerly at startup would make an unconfigured host fail to start at all,
    taking those three offline tools down with it. Resolution is therefore
    deferred to first use, so a missing or malformed credential surfaces as an
    error from ``dry_run_kql`` — the only tool that needs one — rather than as
    a dead server.

    The underlying ``AuthError`` is raised on every call, not cached away: a
    misconfigured host keeps reporting why.
    """

    def __init__(self, factory: Callable[[], CredentialProvider]) -> None:
        self._factory = factory
        self._resolved: CredentialProvider | None = None
        self._lock = threading.Lock()

    def _provider(self) -> CredentialProvider:
        with self._lock:
            if self._resolved is None:
                self._resolved = self._factory()
            return self._resolved

    def get_credentials(self, tenant_key: str = DEFAULT_TENANT_KEY) -> AzureCredentials:
        return self._provider().get_credentials(tenant_key)

    def get_pfx_bytes(self, tenant_key: str = DEFAULT_TENANT_KEY) -> bytes | None:
        # Must delegate: without this, a Key Vault / Vault tenant behind the
        # production LazyCredentialProvider would fall back to cert_path=None.
        return self._provider().get_pfx_bytes(tenant_key)

    def list_tenants(self) -> list[str]:
        return self._provider().list_tenants()

    @property
    def default_tenant_key(self) -> str:
        return self._provider().default_tenant_key

    def rate_limit_configs(self) -> dict[str, RateLimitConfig]:
        # Read once at server start to build the RateLimiter. An unconfigured
        # or malformed host gets the defaults here; the AuthError still
        # surfaces from the first tool call that needs credentials.
        try:
            return self._provider().rate_limit_configs()
        except AuthError:
            return {}


def _build_configured_provider() -> CredentialProvider:
    tenants_file = os.environ.get("MCP_SENTINEL_TENANTS_FILE")
    if tenants_file:
        return JsonFileCredentialProvider(tenants_file)
    return EnvCredentialProvider()


def build_default_token_manager() -> TokenManager:
    """Build the token manager used by the production server.

    Credential loading is lazy — see :class:`LazyCredentialProvider`. This
    function does not raise on a missing Azure configuration.
    """
    return TokenManager(LazyCredentialProvider(_build_configured_provider))
