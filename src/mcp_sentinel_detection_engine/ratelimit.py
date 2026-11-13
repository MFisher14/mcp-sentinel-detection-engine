"""Per-tenant quota and circuit-breaker enforcement for upstream calls.

Mitigates THREAT_MODEL T7. The fan-out semaphore in ``tools._runtime``
bounds *concurrency*; this module bounds *rate*:

- A token bucket per ``(tenant_key, tool_name)``. A call that finds the
  bucket empty fails fast with ``rate_limited`` for that tenant only.
- A circuit breaker per ``tenant_key``. After ``circuit_breaker_threshold``
  consecutive calls end in an upstream 429 (i.e. the client's own retries
  were exhausted), the tenant is cooled off for
  ``circuit_breaker_cooloff_seconds``: calls return ``rate_limited``
  immediately with no HTTP attempt. After the cool-off one probe call is
  let through; success closes the breaker, another 429 re-opens it.

State is process-local. Cluster-wide quota needs a shared store and is
out of scope.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .audit import audit
from .errors import AuthError, RateLimitedError


@dataclass(frozen=True)
class RateLimitConfig:
    requests_per_minute: float = 60.0
    burst: int = 10
    circuit_breaker_threshold: int = 5
    circuit_breaker_cooloff_seconds: float = 300.0

    @classmethod
    def from_mapping(cls, tenant_key: str, raw: Any) -> RateLimitConfig:
        if raw is None:
            return cls()
        if not isinstance(raw, Mapping):
            raise AuthError(f"Tenant '{tenant_key}' rate_limit must be an object")
        allowed = {
            "requests_per_minute",
            "burst",
            "circuit_breaker_threshold",
            "circuit_breaker_cooloff_seconds",
        }
        unknown = set(raw) - allowed
        if unknown:
            raise AuthError(
                f"Tenant '{tenant_key}' rate_limit has unknown keys: {', '.join(sorted(unknown))}"
            )
        defaults = cls()
        try:
            config = cls(
                requests_per_minute=float(
                    raw.get("requests_per_minute", defaults.requests_per_minute)
                ),
                burst=int(raw.get("burst", defaults.burst)),
                circuit_breaker_threshold=int(
                    raw.get("circuit_breaker_threshold", defaults.circuit_breaker_threshold)
                ),
                circuit_breaker_cooloff_seconds=float(
                    raw.get(
                        "circuit_breaker_cooloff_seconds",
                        defaults.circuit_breaker_cooloff_seconds,
                    )
                ),
            )
        except (TypeError, ValueError) as exc:
            raise AuthError(f"Tenant '{tenant_key}' rate_limit values must be numbers") from exc
        if (
            config.requests_per_minute <= 0
            or config.burst < 1
            or config.circuit_breaker_threshold < 1
            or config.circuit_breaker_cooloff_seconds < 0
        ):
            raise AuthError(f"Tenant '{tenant_key}' rate_limit values out of range")
        return config


def parse_rate_limits(tenants_raw: Mapping[str, Any]) -> dict[str, RateLimitConfig]:
    """Parse the optional per-tenant ``rate_limit`` blocks of a tenants config."""
    parsed: dict[str, RateLimitConfig] = {}
    for key, entry in tenants_raw.items():
        if isinstance(entry, Mapping) and "rate_limit" in entry:
            parsed[key] = RateLimitConfig.from_mapping(key, entry["rate_limit"])
    return parsed


class _TokenBucket:
    def __init__(self, capacity: int, refill_per_second: float, now: float) -> None:
        self.capacity = float(capacity)
        self.refill_per_second = refill_per_second
        self.tokens = float(capacity)
        self.updated = now

    def try_take(self, now: float) -> bool:
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
        self.updated = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


@dataclass
class _Breaker:
    consecutive_429s: int = 0
    open_until: float | None = None
    half_open: bool = False


class RateLimiter:
    """Process-wide registry of token buckets and circuit breakers."""

    def __init__(
        self,
        configs: Mapping[str, RateLimitConfig] | None = None,
        *,
        default: RateLimitConfig | None = None,
        time_source: Callable[[], float] | None = None,
    ) -> None:
        self._configs = dict(configs or {})
        self._default = default or RateLimitConfig()
        self._now: Callable[[], float] = time_source or time.monotonic
        self._buckets: dict[tuple[str, str], _TokenBucket] = {}
        self._breakers: dict[str, _Breaker] = {}
        self._lock = threading.Lock()

    def config_for(self, tenant_key: str) -> RateLimitConfig:
        return self._configs.get(tenant_key, self._default)

    def acquire(self, tenant_key: str, tool_name: str) -> None:
        """Raise ``RateLimitedError`` if the call must not proceed."""
        config = self.config_for(tenant_key)
        now = self._now()
        with self._lock:
            breaker = self._breakers.setdefault(tenant_key, _Breaker())
            if breaker.open_until is not None:
                if now < breaker.open_until:
                    raise RateLimitedError(
                        "Tenant is cooling off after repeated upstream rate limiting; retry later"
                    )
                breaker.open_until = None
                breaker.half_open = True
                audit("circuit-breaker-half-open", tenant=tenant_key)
            bucket = self._buckets.get((tenant_key, tool_name))
            if bucket is None:
                bucket = _TokenBucket(config.burst, config.requests_per_minute / 60.0, now)
                self._buckets[(tenant_key, tool_name)] = bucket
            if not bucket.try_take(now):
                audit("rate-limit-quota-exhausted", tenant=tenant_key, tool=tool_name)
                raise RateLimitedError("Per-tenant request quota exhausted; retry later")

    def record_success(self, tenant_key: str) -> None:
        with self._lock:
            breaker = self._breakers.setdefault(tenant_key, _Breaker())
            if breaker.half_open:
                audit("circuit-breaker-closed", tenant=tenant_key)
            breaker.consecutive_429s = 0
            breaker.half_open = False

    def record_rate_limited(self, tenant_key: str) -> None:
        config = self.config_for(tenant_key)
        with self._lock:
            breaker = self._breakers.setdefault(tenant_key, _Breaker())
            breaker.consecutive_429s += 1
            if breaker.half_open or breaker.consecutive_429s >= config.circuit_breaker_threshold:
                breaker.open_until = self._now() + config.circuit_breaker_cooloff_seconds
                breaker.half_open = False
                audit(
                    "circuit-breaker-opened",
                    tenant=tenant_key,
                    consecutive_429s=breaker.consecutive_429s,
                    cooloff_seconds=config.circuit_breaker_cooloff_seconds,
                )
