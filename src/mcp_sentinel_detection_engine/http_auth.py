"""Bearer-token (JWT) validation for the HTTP transport.

The server only *validates* tokens; minting is the operator's job (see
``examples/mint_http_token.py``). Every HTTP MCP request must carry
``Authorization: Bearer <jwt>``. A token is accepted only if:

- it is signed with the configured key (HS256 shared secret, or
  RS256/ES256 public key) — ``alg: none`` and algorithm confusion are
  impossible because the accepted algorithm list is fixed by key type;
- ``iss`` and ``aud`` match this server instance's configured values;
- ``exp`` and ``iat`` are present, ``iat`` is not in the future, the token
  is not expired, and ``exp - iat`` does not exceed the max lifetime
  (15 minutes by default) — a long-lived token is rejected even if its
  signature is valid;
- ``jti`` is present, and (when single-use mode is on) has not been seen
  before.

Rejections are audited with a reason code, never with the token.
"""

from __future__ import annotations

import os
import stat
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jwt

from .errors import AuthError

DEFAULT_MAX_TTL_SECONDS = 15 * 60
_CLOCK_SKEW_SECONDS = 30
_MIN_HS256_SECRET_BYTES = 32

ENV_SECRET_FILE = "MCP_SENTINEL_HTTP_AUTH_SECRET_FILE"  # noqa: S105
ENV_PUBLIC_KEY_FILE = "MCP_SENTINEL_HTTP_AUTH_PUBLIC_KEY_FILE"
ENV_ISSUER = "MCP_SENTINEL_HTTP_AUTH_ISSUER"
ENV_AUDIENCE = "MCP_SENTINEL_HTTP_AUTH_AUDIENCE"
ENV_MAX_TTL = "MCP_SENTINEL_HTTP_AUTH_MAX_TTL_SECONDS"
ENV_SINGLE_USE = "MCP_SENTINEL_HTTP_AUTH_SINGLE_USE"


class TokenRejected(Exception):
    """Raised when a bearer token fails validation. ``reason`` is audit-safe."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _read_key_file(path_str: str, *, secret: bool) -> bytes:
    path = Path(path_str)
    if not path.is_file():
        raise AuthError("HTTP auth key file not found")
    if secret and not sys.platform.startswith("win"):
        mode = path.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise AuthError("HTTP auth secret file permissions are too permissive (need 0600)")
    data = path.read_bytes().strip()
    if not data:
        raise AuthError("HTTP auth key file is empty")
    return data


@dataclass
class BearerTokenValidator:
    key: bytes
    algorithms: list[str]
    issuer: str
    audience: str
    max_ttl_seconds: int = DEFAULT_MAX_TTL_SECONDS
    single_use: bool = False
    time_source: Callable[[], float] = time.time
    _seen_jti: dict[str, float] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __repr__(self) -> str:
        return (
            f"BearerTokenValidator(algorithms={self.algorithms!r}, issuer={self.issuer!r}, "
            f"audience={self.audience!r}, max_ttl_seconds={self.max_ttl_seconds}, "
            f"single_use={self.single_use}, key=***REDACTED***)"
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> BearerTokenValidator:
        source = dict(env) if env is not None else dict(os.environ)
        secret_file = source.get(ENV_SECRET_FILE)
        public_key_file = source.get(ENV_PUBLIC_KEY_FILE)
        if bool(secret_file) == bool(public_key_file):
            raise AuthError(
                f"HTTP transport requires exactly one of {ENV_SECRET_FILE} (HS256) or "
                f"{ENV_PUBLIC_KEY_FILE} (RS256/ES256)"
            )
        issuer = source.get(ENV_ISSUER, "").strip()
        audience = source.get(ENV_AUDIENCE, "").strip()
        if not issuer or not audience:
            raise AuthError(f"HTTP transport requires {ENV_ISSUER} and {ENV_AUDIENCE}")
        if secret_file:
            key = _read_key_file(secret_file, secret=True)
            if len(key) < _MIN_HS256_SECRET_BYTES:
                raise AuthError(f"HS256 secret must be at least {_MIN_HS256_SECRET_BYTES} bytes")
            algorithms = ["HS256"]
        else:
            key = _read_key_file(public_key_file or "", secret=False)
            if b"PRIVATE KEY" in key:
                raise AuthError("HTTP auth public key file contains a private key")
            algorithms = ["RS256", "ES256"]
        try:
            max_ttl = int(source.get(ENV_MAX_TTL, str(DEFAULT_MAX_TTL_SECONDS)))
        except ValueError as exc:
            raise AuthError(f"{ENV_MAX_TTL} must be an integer") from exc
        if not 60 <= max_ttl <= 24 * 3600:
            raise AuthError(f"{ENV_MAX_TTL} must be between 60 and 86400")
        single_use = source.get(ENV_SINGLE_USE, "").strip().lower() in {"1", "true", "yes"}
        return cls(
            key=key,
            algorithms=algorithms,
            issuer=issuer,
            audience=audience,
            max_ttl_seconds=max_ttl,
            single_use=single_use,
        )

    def validate_header(self, header_value: str | None) -> dict[str, Any]:
        if not header_value:
            raise TokenRejected("missing_token")
        scheme, _, token = header_value.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise TokenRejected("malformed_authorization_header")
        return self.validate(token.strip())

    def validate(self, token: str) -> dict[str, Any]:
        now = self.time_source()
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                self.key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
                leeway=_CLOCK_SKEW_SECONDS,
                options={"require": ["exp", "iat", "iss", "aud", "jti"], "verify_iat": False},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenRejected("expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise TokenRejected("wrong_audience") from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenRejected("wrong_issuer") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise TokenRejected("missing_claim") from exc
        except jwt.InvalidSignatureError as exc:
            raise TokenRejected("bad_signature") from exc
        except jwt.PyJWTError as exc:
            raise TokenRejected("invalid_token") from exc

        iat = float(claims["iat"])
        exp = float(claims["exp"])
        if iat > now + _CLOCK_SKEW_SECONDS:
            raise TokenRejected("issued_in_future")
        if exp > now + _CLOCK_SKEW_SECONDS + self.max_ttl_seconds:
            raise TokenRejected("lifetime_too_long")
        if exp - iat > self.max_ttl_seconds:
            raise TokenRejected("lifetime_too_long")
        # PyJWT applies leeway to exp; re-check without it so the configured
        # TTL is the real bound.
        if exp <= now - _CLOCK_SKEW_SECONDS:
            raise TokenRejected("expired")

        jti = str(claims["jti"])
        if self.single_use:
            with self._lock:
                self._seen_jti = {k: v for k, v in self._seen_jti.items() if v > now}
                if jti in self._seen_jti:
                    raise TokenRejected("replayed")
                self._seen_jti[jti] = exp + _CLOCK_SKEW_SECONDS
        return claims
