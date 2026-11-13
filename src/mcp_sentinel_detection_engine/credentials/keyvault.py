"""Azure Key Vault-backed PFX source (issue #10).

Fetches each tenant's App Registration certificate from Key Vault via the
data-plane REST API (``GET {vault}/secrets/{name}``) — the *secret* view of a
Key Vault certificate is the full PFX, base64-encoded, with content type
``application/x-pkcs12``.

Authentication to Key Vault uses a **bootstrap identity** that is distinct
from the per-tenant App Registration the PFX belongs to (the PFX can't be
used to fetch itself). Two bootstrap shapes are supported:

* ``managed_identity`` — the host's system- or user-assigned managed
  identity, via ``IDENTITY_ENDPOINT``/``IDENTITY_HEADER`` (App Service,
  Container Apps, Functions) or the VM/AKS Instance Metadata Service.
* ``app_registration`` — a separate App Registration with a file-based
  certificate, granted only ``Key Vault Secrets User`` on the vault and
  token-scoped to ``https://vault.azure.net/.default``.

No Azure SDK dependency: plain ``httpx`` + ``msal``, both already required.
Every failure surfaces as :class:`AuthError` without the vault URL or the
certificate name, so the error can't act as a tenant/secret-existence oracle.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
import msal

from ..errors import AuthError
from . import base as _base
from .base import (
    PfxSource,
    optional_str,
    read_env,
    require_env_name,
    require_str,
)
from .pfx import normalize_pfx

KEY_VAULT_API_VERSION = "7.4"
_IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"
_IMDS_API_VERSION = "2018-02-01"
_APP_SERVICE_MSI_API_VERSION = "2019-08-01"
_TOKEN_LEEWAY_SECONDS = 60.0

# Key Vault DNS suffix -> AAD resource for that cloud.
_VAULT_SUFFIXES: dict[str, str] = {
    ".vault.azure.net": "https://vault.azure.net",
    ".vault.azure.cn": "https://vault.azure.cn",
    ".vault.usgovcloudapi.net": "https://vault.usgovcloudapi.net",
}
_CERT_NAME_RE = re.compile(r"^[0-9A-Za-z-]{1,127}$")
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_FETCH_FAILED = "Failed to retrieve certificate from Key Vault"


def validate_vault_url(url: str, *, context: str) -> tuple[str, str]:
    """Return ``(normalized_url, aad_resource)`` or raise :class:`AuthError`.

    The error never echoes the URL itself.
    """
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    if (
        parts.scheme != "https"
        or not host
        or parts.username
        or parts.password
        or parts.port not in (None, 443)
        or parts.query
        or parts.fragment
        or parts.path not in ("", "/")
    ):
        raise AuthError(f"{context} url must be an https Key Vault URL with no path or query")
    for suffix, resource in _VAULT_SUFFIXES.items():
        vault_name = host.removesuffix(suffix)
        if host.endswith(suffix) and vault_name and "." not in vault_name:
            return f"https://{host}", resource
    raise AuthError(
        f"{context} url must be a Key Vault host ({', '.join(sorted(_VAULT_SUFFIXES))})"
    )


class BootstrapIdentity:
    """Acquires access tokens for the Key Vault data plane."""

    kind: str = "unknown"

    def get_token(self, resource: str) -> str:
        raise NotImplementedError


class ManagedIdentityBootstrap(BootstrapIdentity):
    """System- or user-assigned managed identity (App Service MSI or IMDS)."""

    kind = "managed_identity"

    def __init__(
        self,
        *,
        client_id: str | None,
        http_client: httpx.Client,
        env: dict[str, str] | None = None,
        time_source: Callable[[], float] | None = None,
    ) -> None:
        self._client_id = client_id
        self._http = http_client
        self._env: dict[str, str] = dict(env) if env is not None else dict(os.environ)
        self._time: Callable[[], float] = time_source or time.time
        self._cache: dict[str, tuple[str, float]] = {}

    def get_token(self, resource: str) -> str:
        cached = self._cache.get(resource)
        now = self._time()
        if cached is not None and cached[1] - _TOKEN_LEEWAY_SECONDS > now:
            return cached[0]
        endpoint = self._env.get("IDENTITY_ENDPOINT")
        header = self._env.get("IDENTITY_HEADER")
        params: dict[str, str] = {"resource": resource}
        if self._client_id:
            params["client_id"] = self._client_id
        if endpoint and header:
            params["api-version"] = _APP_SERVICE_MSI_API_VERSION
            headers = {"X-IDENTITY-HEADER": header}
            url = endpoint
        else:
            params["api-version"] = _IMDS_API_VERSION
            headers = {"Metadata": "true"}
            url = _IMDS_ENDPOINT
        try:
            response = self._http.get(url, params=params, headers=headers)
        except httpx.HTTPError as exc:
            raise AuthError("Managed identity endpoint is unreachable") from exc
        if response.status_code != 200:
            raise AuthError(f"Managed identity token request failed (HTTP {response.status_code})")
        token, expires_at = _parse_msi_token(response, now)
        self._cache[resource] = (token, expires_at)
        return token


def _parse_msi_token(response: httpx.Response, now: float) -> tuple[str, float]:
    try:
        payload = response.json()
    except ValueError as exc:
        raise AuthError("Managed identity returned a malformed token response") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("access_token"), str):
        raise AuthError("Managed identity returned a malformed token response")
    expires_at = now + 300.0
    try:
        if payload.get("expires_on") is not None:
            expires_at = float(payload["expires_on"])
        elif payload.get("expires_in") is not None:
            expires_at = now + float(payload["expires_in"])
    except (TypeError, ValueError):
        pass
    return str(payload["access_token"]), expires_at


MsalFactory = Callable[..., Any]


def _default_msal_factory(
    *, client_id: str, authority: str, client_credential: dict[str, Any]
) -> Any:
    return msal.ConfidentialClientApplication(
        client_id=client_id, authority=authority, client_credential=client_credential
    )


class AppRegistrationBootstrap(BootstrapIdentity):
    """A *separate* App Registration whose only grant is reading vault secrets."""

    kind = "app_registration"

    def __init__(
        self,
        *,
        tenant_id: str,
        client_id: str,
        cert_path: str,
        cert_passphrase: str | None,
        msal_factory: MsalFactory | None = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._cert_path = cert_path
        self._passphrase = cert_passphrase
        self._factory = msal_factory or _default_msal_factory
        self._app: Any = None

    def get_token(self, resource: str) -> str:
        if self._app is None:
            credential: dict[str, Any] = {"private_key_pfx_path": self._cert_path}
            if self._passphrase:
                credential["passphrase"] = self._passphrase
            try:
                self._app = self._factory(
                    client_id=self._client_id,
                    authority=f"https://login.microsoftonline.com/{self._tenant_id}",
                    client_credential=credential,
                )
            except (ValueError, OSError) as exc:
                raise AuthError("Key Vault bootstrap identity could not be initialised") from exc
        result = self._app.acquire_token_for_client(scopes=[f"{resource}/.default"])
        if not isinstance(result, dict) or "access_token" not in result:
            error_code = result.get("error") if isinstance(result, dict) else "unknown_error"
            raise AuthError(f"Key Vault bootstrap token acquisition failed: {error_code}")
        return str(result["access_token"])


@dataclass(frozen=True)
class KeyVaultConfig:
    url: str
    resource: str
    certificate_name: str
    passphrase_env: str | None


class KeyVaultPfxSource(PfxSource):
    """Fetches one tenant's PFX from Azure Key Vault."""

    store = "key_vault"

    def __init__(
        self,
        config: KeyVaultConfig,
        bootstrap: BootstrapIdentity,
        *,
        env: dict[str, str] | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._config = config
        self._bootstrap = bootstrap
        self._env: dict[str, str] = dict(env) if env is not None else dict(os.environ)
        self._http = http_client or _base.new_http_client()

    @property
    def bootstrap(self) -> BootstrapIdentity:
        return self._bootstrap

    def fetch_pfx(self) -> bytes:
        token = self._bootstrap.get_token(self._config.resource)
        url = f"{self._config.url}/secrets/{self._config.certificate_name}"
        try:
            response = self._http.get(
                url,
                params={"api-version": KEY_VAULT_API_VERSION},
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise AuthError(f"{_FETCH_FAILED} (network error)") from exc
        if response.status_code != 200:
            raise AuthError(f"{_FETCH_FAILED} (HTTP {response.status_code})")
        try:
            payload = response.json()
        except ValueError as exc:
            raise AuthError(f"{_FETCH_FAILED} (malformed response)") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("value"), str):
            raise AuthError(f"{_FETCH_FAILED} (malformed response)")
        content_type = payload.get("contentType")
        if content_type not in (None, "application/x-pkcs12"):
            raise AuthError(
                f"{_FETCH_FAILED} (certificate must use the PKCS#12 content type, not PEM)"
            )
        try:
            raw = base64.b64decode(payload["value"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise AuthError(f"{_FETCH_FAILED} (secret value is not base64)") from exc
        passphrase = None
        if self._config.passphrase_env is not None:
            passphrase = read_env(self._env, self._config.passphrase_env, what="passphrase")
        return normalize_pfx(raw, passphrase)


def parse_key_vault_block(
    tenant_key: str,
    block: dict[str, Any],
    env: dict[str, str],
    *,
    http_client: httpx.Client | None = None,
    msal_factory: MsalFactory | None = None,
) -> KeyVaultPfxSource:
    """Validate a tenants-JSON ``key_vault`` block and build its lazy source."""
    context = f"Tenant '{tenant_key}' key_vault"
    allowed = {"url", "certificate_name", "bootstrap_identity", "passphrase_env"}
    unknown = sorted(set(block) - allowed)
    if unknown:
        raise AuthError(f"{context} has unknown fields: {', '.join(unknown)}")
    url, resource = validate_vault_url(require_str(block, "url", context=context), context=context)
    cert_name = require_str(block, "certificate_name", context=context)
    if not _CERT_NAME_RE.match(cert_name):
        raise AuthError(f"{context} certificate_name must match [0-9A-Za-z-]{{1,127}}")
    passphrase_env = (
        require_env_name(block, "passphrase_env", context=context)
        if block.get("passphrase_env") is not None
        else None
    )
    config = KeyVaultConfig(
        url=url, resource=resource, certificate_name=cert_name, passphrase_env=passphrase_env
    )
    http = http_client or _base.new_http_client()
    bootstrap = _parse_bootstrap(
        context, block.get("bootstrap_identity"), env, http=http, msal_factory=msal_factory
    )
    return KeyVaultPfxSource(config, bootstrap, env=env, http_client=http)


def _parse_bootstrap(
    context: str,
    raw: Any,
    env: dict[str, str],
    *,
    http: httpx.Client,
    msal_factory: MsalFactory | None,
) -> BootstrapIdentity:
    if raw is None:
        raw = {"type": "managed_identity"}
    if not isinstance(raw, dict):
        raise AuthError(f"{context} bootstrap_identity must be an object")
    bctx = f"{context}.bootstrap_identity"
    kind = raw.get("type")
    if kind == "managed_identity":
        unknown = sorted(set(raw) - {"type", "client_id"})
        if unknown:
            raise AuthError(f"{bctx} has unknown fields: {', '.join(unknown)}")
        client_id = optional_str(raw, "client_id", context=bctx)
        if client_id is not None and not _GUID_RE.match(client_id):
            raise AuthError(f"{bctx} client_id must be a GUID")
        return ManagedIdentityBootstrap(client_id=client_id, http_client=http, env=env)
    if kind == "app_registration":
        allowed = {"type", "tenant_id", "client_id", "cert_path", "cert_passphrase_env"}
        unknown = sorted(set(raw) - allowed)
        if unknown:
            raise AuthError(f"{bctx} has unknown fields: {', '.join(unknown)}")
        tenant_id = require_str(raw, "tenant_id", context=bctx)
        client_id = require_str(raw, "client_id", context=bctx)
        cert_path = require_str(raw, "cert_path", context=bctx)
        if not (os.path.isfile(cert_path) and os.access(cert_path, os.R_OK)):
            raise AuthError(f"{bctx} cert_path is not a readable file")
        passphrase = None
        if raw.get("cert_passphrase_env") is not None:
            name = require_env_name(raw, "cert_passphrase_env", context=bctx)
            passphrase = read_env(env, name, what="bootstrap passphrase")
        return AppRegistrationBootstrap(
            tenant_id=tenant_id,
            client_id=client_id,
            cert_path=cert_path,
            cert_passphrase=passphrase,
            msal_factory=msal_factory,
        )
    raise AuthError(f"{bctx} type must be 'managed_identity' or 'app_registration'")
