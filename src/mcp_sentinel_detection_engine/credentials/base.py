"""Base types for secret-store PFX sources."""

from __future__ import annotations

import re
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from ..audit import audit, audit_error
from ..errors import AuthError

DEFAULT_PFX_CACHE_SECONDS = 3600.0
DEFAULT_HTTP_TIMEOUT_SECONDS = 10.0

ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


class PfxSource(ABC):
    """Fetches the PFX bundle for exactly one tenant from a secret store."""

    #: Short, non-sensitive backend label used in audit records.
    store: str = "unknown"

    @abstractmethod
    def fetch_pfx(self) -> bytes:
        """Return unencrypted PFX bytes.

        Implementations must raise :class:`AuthError` with a message that does
        not reveal the store location, secret name, or token source.
        """


class CachingPfxSource:
    """Thread-safe, time-bounded cache in front of a :class:`PfxSource`.

    The TTL bounds how long a rotated certificate takes to be picked up: the
    token manager re-reads ``get_pfx_bytes`` on every token refresh and rebuilds
    its MSAL app when the bytes change.
    """

    def __init__(
        self,
        source: PfxSource,
        *,
        tenant_key: str,
        ttl_seconds: float = DEFAULT_PFX_CACHE_SECONDS,
        time_source: Callable[[], float] | None = None,
    ) -> None:
        self._source = source
        self._tenant_key = tenant_key
        self._ttl = ttl_seconds
        self._time: Callable[[], float] = time_source or time.monotonic
        self._lock = threading.Lock()
        self._value: bytes | None = None
        self._fetched_at = 0.0

    @property
    def source(self) -> PfxSource:
        return self._source

    def get(self) -> bytes:
        with self._lock:
            now = self._time()
            if self._value is not None and now - self._fetched_at < self._ttl:
                return self._value
            try:
                value = self._source.fetch_pfx()
            except Exception as exc:
                audit_error(
                    "secret-store-fetch-failed",
                    tenant=self._tenant_key,
                    store=self._source.store,
                    error_class=exc.__class__.__name__,
                )
                if isinstance(exc, AuthError):
                    raise
                raise AuthError("Failed to retrieve certificate from secret store") from exc
            # Audit the fetch, never the body (THREAT_MODEL T8).
            audit(
                "secret-store-fetch-succeeded",
                tenant=self._tenant_key,
                store=self._source.store,
                rotated=self._value is not None and value != self._value,
            )
            self._value = value
            self._fetched_at = now
            return value


def require_str(block: dict[str, Any], field: str, *, context: str) -> str:
    value = block.get(field)
    if not isinstance(value, str) or not value.strip():
        raise AuthError(f"{context} missing required string field '{field}'")
    return value.strip()


def optional_str(block: dict[str, Any], field: str, *, context: str) -> str | None:
    value = block.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise AuthError(f"{context} field '{field}' must be a non-empty string")
    return value.strip()


def require_env_name(block: dict[str, Any], field: str, *, context: str) -> str:
    value = require_str(block, field, context=context)
    if not ENV_NAME_RE.match(value):
        raise AuthError(f"{context} field '{field}' must name an environment variable")
    return value


def read_env(env: dict[str, str], name: str, *, what: str) -> str:
    value = env.get(name)
    if not value:
        # Name the *kind* of secret, not the variable — avoids leaking config
        # layout to the MCP client.
        raise AuthError(f"Secret-store {what} is not available in the environment")
    return value
