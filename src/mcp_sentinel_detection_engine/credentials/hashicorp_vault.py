"""HashiCorp Vault KV-v2-backed PFX source (issue #11).

Reads ``<address>/v1/<mount>/data/<path>``; the secret must carry a
``pfx_base64`` key and may carry a ``passphrase`` key. The Vault token comes
from one of three sources:

* ``token`` — a token (optionally a *response-wrapped* token, unwrapped once
  via ``sys/wrapping/unwrap``) read from an environment variable.
* ``approle`` — ``role_id`` / ``secret_id`` read from environment variables.
* ``kubernetes`` — the pod's service-account JWT read from a file.

Tokens are renewed with ``auth/token/renew-self`` once their remaining TTL
drops under the same 60-second leeway the OAuth token cache uses; tokens
that cannot be renewed are replaced by logging in again when the auth method
allows it. All failures raise :class:`AuthError` without the Vault address,
secret path, or token source.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from ..errors import AuthError
from . import base as _base
from .base import PfxSource, optional_str, read_env, require_env_name, require_str
from .pfx import normalize_pfx

_RENEW_LEEWAY_SECONDS = 60.0
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_DEFAULT_K8S_JWT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_FETCH_FAILED = "Failed to retrieve certificate from Vault"


def _validate_address(address: str, *, context: str) -> str:
    parts = urlsplit(address.strip())
    host = (parts.hostname or "").lower()
    if not host or parts.username or parts.password or parts.query or parts.fragment:
        raise AuthError(f"{context} address must be a bare Vault base URL")
    if parts.path not in ("", "/"):
        raise AuthError(f"{context} address must not include a path")
    if parts.scheme == "https" or (parts.scheme == "http" and host in _LOCAL_HOSTS):
        return f"{parts.scheme}://{parts.netloc}"
    raise AuthError(f"{context} address must use https (http only for localhost dev servers)")


def _validate_path(value: str, *, field: str, context: str) -> str:
    segments = value.strip("/").split("/")
    if not segments or any(not _SEGMENT_RE.match(seg) or seg in (".", "..") for seg in segments):
        raise AuthError(f"{context} {field} must be '/'-separated [A-Za-z0-9_.-] segments")
    return "/".join(segments)


@dataclass(frozen=True)
class VaultAuth:
    method: str  # "token" | "approle" | "kubernetes"
    mount: str
    token_env: str | None = None
    wrapped: bool = False
    role_id_env: str | None = None
    secret_id_env: str | None = None
    role: str | None = None
    jwt_path: str | None = None

    @property
    def can_relogin(self) -> bool:
        return self.method in ("approle", "kubernetes")


@dataclass(frozen=True)
class VaultConfig:
    address: str
    mount: str
    path: str
    namespace: str | None
    auth: VaultAuth


@dataclass
class _VaultToken:
    value: str
    expires_at: float | None  # None == no expiry (ttl 0)
    renewable: bool


class VaultPfxSource(PfxSource):
    """Fetches one tenant's PFX from a HashiCorp Vault KV-v2 secret."""

    store = "hashicorp_vault"

    def __init__(
        self,
        config: VaultConfig,
        *,
        env: dict[str, str] | None = None,
        http_client: httpx.Client | None = None,
        time_source: Callable[[], float] | None = None,
    ) -> None:
        self._config = config
        self._env: dict[str, str] = dict(env) if env is not None else dict(os.environ)
        self._http = http_client or _base.new_http_client()
        self._time: Callable[[], float] = time_source or time.time
        self._token: _VaultToken | None = None

    # -- HTTP -----------------------------------------------------------------

    def _call(
        self,
        method: str,
        api_path: str,
        *,
        token: str | None = None,
        json: dict[str, Any] | None = None,
        what: str,
    ) -> dict[str, Any]:
        headers: dict[str, str] = {"Accept": "application/json"}
        if token is not None:
            headers["X-Vault-Token"] = token
        if self._config.namespace:
            headers["X-Vault-Namespace"] = self._config.namespace
        try:
            response = self._http.request(
                method, f"{self._config.address}/v1/{api_path}", headers=headers, json=json
            )
        except httpx.HTTPError as exc:
            raise AuthError(f"Vault {what} failed (network error)") from exc
        if response.status_code != 200:
            raise _VaultHTTPError(f"Vault {what} failed (HTTP {response.status_code})")
        try:
            payload = response.json()
        except ValueError as exc:
            raise AuthError(f"Vault {what} returned a malformed response") from exc
        if not isinstance(payload, dict):
            raise AuthError(f"Vault {what} returned a malformed response")
        return payload

    # -- Token lifecycle --------------------------------------------------------

    def _token_from_auth_block(self, payload: dict[str, Any], *, what: str) -> _VaultToken:
        auth = payload.get("auth")
        if not isinstance(auth, dict) or not isinstance(auth.get("client_token"), str):
            raise AuthError(f"Vault {what} returned no client token")
        lease = auth.get("lease_duration")
        ttl = float(lease) if isinstance(lease, int | float) else 0.0
        return _VaultToken(
            value=auth["client_token"],
            expires_at=self._time() + ttl if ttl > 0 else None,
            renewable=bool(auth.get("renewable", False)),
        )

    def _login(self) -> _VaultToken:
        auth = self._config.auth
        if auth.method == "token":
            assert auth.token_env is not None  # noqa: S101 - enforced by parser
            raw = read_env(self._env, auth.token_env, what="token")
            if auth.wrapped:
                unwrapped = self._call("POST", "sys/wrapping/unwrap", token=raw, what="unwrap")
                return self._token_from_auth_block(unwrapped, what="unwrap")
            lookup = self._call("GET", "auth/token/lookup-self", token=raw, what="token lookup")
            data = lookup.get("data")
            ttl = data.get("ttl") if isinstance(data, dict) else None
            renewable = bool(data.get("renewable", False)) if isinstance(data, dict) else False
            ttl_f = float(ttl) if isinstance(ttl, int | float) else 0.0
            return _VaultToken(
                value=raw,
                expires_at=self._time() + ttl_f if ttl_f > 0 else None,
                renewable=renewable,
            )
        if auth.method == "approle":
            assert auth.role_id_env is not None and auth.secret_id_env is not None  # noqa: S101
            body = {
                "role_id": read_env(self._env, auth.role_id_env, what="AppRole role_id"),
                "secret_id": read_env(self._env, auth.secret_id_env, what="AppRole secret_id"),
            }
        else:  # kubernetes
            assert auth.role is not None and auth.jwt_path is not None  # noqa: S101
            try:
                jwt = Path(auth.jwt_path).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise AuthError("Vault Kubernetes service-account token is unreadable") from exc
            if not jwt:
                raise AuthError("Vault Kubernetes service-account token is empty")
            body = {"role": auth.role, "jwt": jwt}
        payload = self._call("POST", f"auth/{auth.mount}/login", json=body, what="login")
        return self._token_from_auth_block(payload, what="login")

    def _ensure_token(self) -> str:
        token = self._token
        if token is None:
            token = self._login()
        elif token.expires_at is not None and token.expires_at - self._time() < (
            _RENEW_LEEWAY_SECONDS
        ):
            token = self._refresh(token)
        self._token = token
        return token.value

    def _refresh(self, token: _VaultToken) -> _VaultToken:
        if token.renewable:
            try:
                payload = self._call(
                    "POST", "auth/token/renew-self", token=token.value, json={}, what="renewal"
                )
                return self._token_from_auth_block(payload, what="renewal")
            except AuthError:
                if not self._config.auth.can_relogin:
                    raise
        if self._config.auth.can_relogin:
            return self._login()
        # Static token near expiry and not renewable: use it until Vault says no.
        return token

    # -- Fetch -------------------------------------------------------------------

    def fetch_pfx(self) -> bytes:
        api_path = f"{self._config.mount}/data/{self._config.path}"
        token = self._ensure_token()
        try:
            payload = self._call("GET", api_path, token=token, what="secret read")
        except _VaultHTTPError:
            if not self._config.auth.can_relogin:
                raise
            # Token may have been revoked out-of-band; one fresh login, then give up.
            self._token = None
            payload = self._call("GET", api_path, token=self._ensure_token(), what="secret read")
        outer = payload.get("data")
        secret = outer.get("data") if isinstance(outer, dict) else None
        if not isinstance(secret, dict) or not isinstance(secret.get("pfx_base64"), str):
            raise AuthError(f"{_FETCH_FAILED} (secret has no pfx_base64 key)")
        passphrase = secret.get("passphrase")
        if passphrase is not None and not isinstance(passphrase, str):
            raise AuthError(f"{_FETCH_FAILED} (passphrase must be a string)")
        try:
            raw = base64.b64decode(secret["pfx_base64"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise AuthError(f"{_FETCH_FAILED} (pfx_base64 is not base64)") from exc
        return normalize_pfx(raw, passphrase or None)


class _VaultHTTPError(AuthError):
    """Non-200 from Vault (kept distinct so a 403 can trigger one re-login)."""


def parse_vault_block(
    tenant_key: str,
    block: dict[str, Any],
    env: dict[str, str],
    *,
    http_client: httpx.Client | None = None,
    time_source: Callable[[], float] | None = None,
) -> VaultPfxSource:
    """Validate a tenants-JSON ``vault`` block and build its lazy source."""
    context = f"Tenant '{tenant_key}' vault"
    unknown = sorted(set(block) - {"address", "mount", "path", "namespace", "auth"})
    if unknown:
        raise AuthError(f"{context} has unknown fields: {', '.join(unknown)}")
    address = _validate_address(require_str(block, "address", context=context), context=context)
    mount = _validate_path(
        require_str(block, "mount", context=context), field="mount", context=context
    )
    path = _validate_path(
        require_str(block, "path", context=context), field="path", context=context
    )
    namespace = optional_str(block, "namespace", context=context)
    if namespace is not None:
        namespace = _validate_path(namespace, field="namespace", context=context)
    config = VaultConfig(
        address=address,
        mount=mount,
        path=path,
        namespace=namespace,
        auth=_parse_auth(context, block.get("auth")),
    )
    return VaultPfxSource(config, env=env, http_client=http_client, time_source=time_source)


def _parse_auth(context: str, raw: Any) -> VaultAuth:
    actx = f"{context}.auth"
    if not isinstance(raw, dict):
        raise AuthError(f"{actx} must be an object")
    method = raw.get("method")
    if method == "token":
        _reject_unknown(actx, raw, {"method", "token_env", "wrapped"})
        wrapped = raw.get("wrapped", False)
        if not isinstance(wrapped, bool):
            raise AuthError(f"{actx} wrapped must be a boolean")
        return VaultAuth(
            method="token",
            mount="token",
            token_env=require_env_name(raw, "token_env", context=actx),
            wrapped=wrapped,
        )
    if method == "approle":
        _reject_unknown(actx, raw, {"method", "role_id_env", "secret_id_env", "mount"})
        return VaultAuth(
            method="approle",
            mount=_validate_path(raw.get("mount") or "approle", field="mount", context=actx),
            role_id_env=require_env_name(raw, "role_id_env", context=actx),
            secret_id_env=require_env_name(raw, "secret_id_env", context=actx),
        )
    if method == "kubernetes":
        _reject_unknown(actx, raw, {"method", "role", "jwt_path", "mount"})
        role = require_str(raw, "role", context=actx)
        if not _SEGMENT_RE.match(role):
            raise AuthError(f"{actx} role must match [A-Za-z0-9_.-]")
        return VaultAuth(
            method="kubernetes",
            mount=_validate_path(raw.get("mount") or "kubernetes", field="mount", context=actx),
            role=role,
            jwt_path=optional_str(raw, "jwt_path", context=actx) or _DEFAULT_K8S_JWT_PATH,
        )
    raise AuthError(f"{actx} method must be one of 'token', 'approle', 'kubernetes'")


def _reject_unknown(context: str, raw: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise AuthError(f"{context} has unknown fields: {', '.join(unknown)}")
