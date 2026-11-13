"""Tests for per-tenant quota and circuit-breaker enforcement (#4)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pytest

from mcp_sentinel_detection_engine.errors import AuthError, RateLimitedError
from mcp_sentinel_detection_engine.ratelimit import RateLimitConfig, RateLimiter
from mcp_sentinel_detection_engine.tools import dry_run


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_bucket_allows_burst_then_refills() -> None:
    clock = Clock()
    limiter = RateLimiter(
        {"t": RateLimitConfig(requests_per_minute=60, burst=2)}, time_source=clock
    )
    limiter.acquire("t", "dry_run_kql")
    limiter.acquire("t", "dry_run_kql")
    with pytest.raises(RateLimitedError, match="quota"):
        limiter.acquire("t", "dry_run_kql")
    clock.now += 1.0  # 1 token/second
    limiter.acquire("t", "dry_run_kql")


def test_buckets_are_per_tenant_and_tool() -> None:
    limiter = RateLimiter(default=RateLimitConfig(burst=1), time_source=Clock())
    limiter.acquire("a", "dry_run_kql")
    limiter.acquire("b", "dry_run_kql")
    limiter.acquire("a", "validate_kql_against_schema")
    with pytest.raises(RateLimitedError):
        limiter.acquire("a", "dry_run_kql")


def test_circuit_breaker_opens_half_opens_and_closes() -> None:
    clock = Clock()
    config = RateLimitConfig(
        burst=100, circuit_breaker_threshold=2, circuit_breaker_cooloff_seconds=300
    )
    limiter = RateLimiter({"t": config}, time_source=clock)
    limiter.record_rate_limited("t")
    limiter.acquire("t", "x")  # one 429 is below threshold
    limiter.record_rate_limited("t")
    with pytest.raises(RateLimitedError, match="cooling off"):
        limiter.acquire("t", "x")
    clock.now += 301
    limiter.acquire("t", "x")  # half-open probe allowed
    limiter.record_rate_limited("t")  # probe fails → re-open immediately
    with pytest.raises(RateLimitedError, match="cooling off"):
        limiter.acquire("t", "x")
    clock.now += 301
    limiter.acquire("t", "x")
    limiter.record_success("t")
    limiter.record_rate_limited("t")  # counter was reset; threshold is 2
    limiter.acquire("t", "x")


def test_success_resets_consecutive_count() -> None:
    limiter = RateLimiter(
        default=RateLimitConfig(burst=100, circuit_breaker_threshold=2), time_source=Clock()
    )
    limiter.record_rate_limited("t")
    limiter.record_success("t")
    limiter.record_rate_limited("t")
    limiter.acquire("t", "x")


@pytest.mark.parametrize(
    "raw",
    [
        "nope",
        {"burst": 0},
        {"requests_per_minute": -1},
        {"burst": "many"},
        {"unexpected": 1},
    ],
)
def test_config_validation(raw: object) -> None:
    with pytest.raises(AuthError):
        RateLimitConfig.from_mapping("t", raw)


def test_tenants_file_rate_limit_block(tmp_path: Path) -> None:
    from mcp_sentinel_detection_engine.auth import JsonFileCredentialProvider

    pfx = tmp_path / "c.pfx"
    pfx.write_bytes(b"x")
    cfg = tmp_path / "tenants.json"
    cfg.write_text(
        json.dumps(
            {
                "default": "contoso",
                "tenants": {
                    "contoso": {
                        "tenant_id": "t",
                        "client_id": "c",
                        "cert_path": str(pfx),
                        "workspace_id": "55555555-5555-5555-5555-555555555555",
                        "rate_limit": {"requests_per_minute": 6, "burst": 2},
                    }
                },
            }
        )
    )
    os.chmod(cfg, 0o600)
    provider = JsonFileCredentialProvider(cfg, env={})
    assert provider.rate_limit_configs()["contoso"] == RateLimitConfig(
        requests_per_minute=6, burst=2
    )


async def test_fan_out_quota_isolated_per_tenant(make_multi_tenant_context) -> None:
    from mcp_sentinel_detection_engine.tool_context import ToolContext

    hits: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hits.append(request.headers["Authorization"])
        return httpx.Response(200, json={"tables": []})

    ctx, _ = make_multi_tenant_context(handler)
    limiter = RateLimiter(
        {"fabrikam": RateLimitConfig(burst=1, requests_per_minute=1)}, time_source=Clock()
    )
    ctx._rate_limiter = limiter
    assert isinstance(ctx, ToolContext)
    async with ctx:
        await dry_run.run(ctx, {"query": "SecurityEvent", "tenant": "*"})
        result = await dry_run.run(ctx, {"query": "SecurityEvent", "tenant": "*"})

    by_tenant = {r["tenant"]: r for r in result["results"]}
    assert "result" in by_tenant["contoso"]
    assert by_tenant["fabrikam"]["error"]["code"] == "rate_limited"
    assert hits.count("Bearer token-fabrikam") == 1
    assert hits.count("Bearer token-contoso") == 2


async def test_breaker_short_circuits_without_http(make_context) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429)

    ctx, _ = make_context(handler)
    ctx._rate_limiter = RateLimiter(
        default=RateLimitConfig(burst=100, circuit_breaker_threshold=1), time_source=Clock()
    )
    async with ctx:
        with pytest.raises(RateLimitedError, match="retries exhausted"):
            await dry_run.run(ctx, {"query": "SecurityEvent"})
        upstream_calls = calls
        with pytest.raises(RateLimitedError, match="cooling off"):
            await dry_run.run(ctx, {"query": "SecurityEvent"})
    assert calls == upstream_calls


def test_lazy_provider_delegates_rate_limits_and_tolerates_missing_config() -> None:
    from mcp_sentinel_detection_engine.auth import CredentialProvider, LazyCredentialProvider

    class _WithLimits(CredentialProvider):
        def get_credentials(self, tenant_key: str = "default"):
            raise NotImplementedError

        def rate_limit_configs(self) -> dict[str, RateLimitConfig]:
            return {"t": RateLimitConfig(burst=3)}

    assert LazyCredentialProvider(_WithLimits).rate_limit_configs() == {
        "t": RateLimitConfig(burst=3)
    }

    def _broken() -> CredentialProvider:
        raise AuthError("missing")

    assert LazyCredentialProvider(_broken).rate_limit_configs() == {}
