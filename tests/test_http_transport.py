"""Tests for the HTTP transport and bearer-token auth (#2, #3)."""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any

import jwt
import pytest
from starlette.testclient import TestClient

from mcp_sentinel_detection_engine import audit as audit_module
from mcp_sentinel_detection_engine.auth import LazyCredentialProvider, TokenManager
from mcp_sentinel_detection_engine.errors import AuthError
from mcp_sentinel_detection_engine.http_auth import BearerTokenValidator, TokenRejected
from mcp_sentinel_detection_engine.http_transport import HttpSettings, build_http_app
from mcp_sentinel_detection_engine.server import _parse_args, build_server

SECRET = b"s" * 48
ISS = "https://mcp-gateway.example"
AUD = "mcp-sentinel-detection-engine/test-instance"


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.formatter_impl = audit_module._JsonFormatter()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.formatter_impl.format(record))


@pytest.fixture
def audit_lines() -> Any:
    handler = _Capture()
    logger = logging.getLogger("mcp_sentinel_detection_engine.audit")
    logger.addHandler(handler)
    yield handler.lines
    logger.removeHandler(handler)


def _validator(**kw: Any) -> BearerTokenValidator:
    return BearerTokenValidator(key=SECRET, algorithms=["HS256"], issuer=ISS, audience=AUD, **kw)


def _token(*, key: bytes = SECRET, ttl: int = 300, iat_offset: int = 0, **overrides: Any) -> str:
    now = int(time.time()) + iat_offset
    claims: dict[str, Any] = {
        "iss": ISS,
        "aud": AUD,
        "sub": "ci-runner",
        "iat": now,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="HS256")


# ---------- validator ----------


def test_valid_token_accepted() -> None:
    claims = _validator().validate_header(f"Bearer {_token()}")
    assert claims["sub"] == "ci-runner"


@pytest.mark.parametrize(
    ("header", "reason"),
    [
        (None, "missing_token"),
        ("Basic abc", "malformed_authorization_header"),
        ("Bearer ", "malformed_authorization_header"),
        ("Bearer not-a-jwt", "invalid_token"),
    ],
)
def test_malformed_headers_rejected(header: str | None, reason: str) -> None:
    with pytest.raises(TokenRejected) as exc_info:
        _validator().validate_header(header)
    assert exc_info.value.reason == reason


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"key": b"x" * 48}, "bad_signature"),
        ({"aud": "someone-else"}, "wrong_audience"),
        ({"iss": "https://evil.example"}, "wrong_issuer"),
        ({"jti": None}, "missing_claim"),
        ({"ttl": 3600}, "lifetime_too_long"),
        ({"iat_offset": -1000, "ttl": 300}, "expired"),
        ({"iat_offset": 600, "ttl": 300}, "issued_in_future"),
    ],
)
def test_bad_tokens_rejected(kwargs: dict[str, Any], reason: str) -> None:
    with pytest.raises(TokenRejected) as exc_info:
        _validator().validate(_token(**kwargs))
    assert exc_info.value.reason == reason


def test_alg_none_rejected() -> None:
    now = int(time.time())
    token = jwt.encode(
        {"iss": ISS, "aud": AUD, "iat": now, "exp": now + 60, "jti": "x"}, "", algorithm="none"
    )
    with pytest.raises(TokenRejected):
        _validator().validate(token)


def test_single_use_rejects_replay() -> None:
    validator = _validator(single_use=True)
    token = _token()
    validator.validate(token)
    with pytest.raises(TokenRejected) as exc_info:
        validator.validate(token)
    assert exc_info.value.reason == "replayed"


def test_reuse_allowed_by_default() -> None:
    validator = _validator()
    token = _token()
    validator.validate(token)
    validator.validate(token)


def test_repr_redacts_key() -> None:
    assert "sss" not in repr(_validator())


def _secret_file(tmp_path: Path, data: bytes = SECRET, mode: int = 0o600) -> str:
    path = tmp_path / "secret"
    path.write_bytes(data)
    os.chmod(path, mode)
    return str(path)


def test_from_env_hs256(tmp_path: Path) -> None:
    v = BearerTokenValidator.from_env(
        {
            "MCP_SENTINEL_HTTP_AUTH_SECRET_FILE": _secret_file(tmp_path),
            "MCP_SENTINEL_HTTP_AUTH_ISSUER": ISS,
            "MCP_SENTINEL_HTTP_AUTH_AUDIENCE": AUD,
            "MCP_SENTINEL_HTTP_AUTH_SINGLE_USE": "true",
        }
    )
    assert v.algorithms == ["HS256"] and v.single_use and v.max_ttl_seconds == 900


@pytest.mark.parametrize(
    ("env_builder", "match"),
    [
        (lambda p: {}, "exactly one"),
        (lambda p: {"MCP_SENTINEL_HTTP_AUTH_SECRET_FILE": _secret_file(p)}, "ISSUER"),
        (
            lambda p: {
                "MCP_SENTINEL_HTTP_AUTH_SECRET_FILE": _secret_file(p, b"short"),
                "MCP_SENTINEL_HTTP_AUTH_ISSUER": ISS,
                "MCP_SENTINEL_HTTP_AUTH_AUDIENCE": AUD,
            },
            "at least 32",
        ),
        (
            lambda p: {
                "MCP_SENTINEL_HTTP_AUTH_SECRET_FILE": _secret_file(p, mode=0o644),
                "MCP_SENTINEL_HTTP_AUTH_ISSUER": ISS,
                "MCP_SENTINEL_HTTP_AUTH_AUDIENCE": AUD,
            },
            "permissive",
        ),
        (
            lambda p: {
                "MCP_SENTINEL_HTTP_AUTH_SECRET_FILE": _secret_file(p),
                "MCP_SENTINEL_HTTP_AUTH_ISSUER": ISS,
                "MCP_SENTINEL_HTTP_AUTH_AUDIENCE": AUD,
                "MCP_SENTINEL_HTTP_AUTH_MAX_TTL_SECONDS": "999999",
            },
            "between",
        ),
    ],
)
def test_from_env_misconfig(tmp_path: Path, env_builder: Any, match: str) -> None:
    with pytest.raises(AuthError, match=match):
        BearerTokenValidator.from_env(env_builder(tmp_path))


def test_from_env_rejects_private_key_as_public(tmp_path: Path) -> None:
    key = tmp_path / "pub.pem"
    key.write_text("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n")
    with pytest.raises(AuthError, match="private key"):
        BearerTokenValidator.from_env(
            {
                "MCP_SENTINEL_HTTP_AUTH_PUBLIC_KEY_FILE": str(key),
                "MCP_SENTINEL_HTTP_AUTH_ISSUER": ISS,
                "MCP_SENTINEL_HTTP_AUTH_AUDIENCE": AUD,
            }
        )


def test_rs256_public_key(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = tmp_path / "pub.pem"
    pub.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    v = BearerTokenValidator.from_env(
        {
            "MCP_SENTINEL_HTTP_AUTH_PUBLIC_KEY_FILE": str(pub),
            "MCP_SENTINEL_HTTP_AUTH_ISSUER": ISS,
            "MCP_SENTINEL_HTTP_AUTH_AUDIENCE": AUD,
        }
    )
    now = int(time.time())
    token = jwt.encode(
        {"iss": ISS, "aud": AUD, "iat": now, "exp": now + 60, "jti": "a"},
        private,
        algorithm="RS256",
    )
    assert v.validate(token)["jti"] == "a"
    # Algorithm confusion: HS256 signed with the public key bytes must fail.
    # PyJWT refuses to *create* such a token, so build it by hand.
    import base64
    import hashlib
    import hmac

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    signing_input = (
        b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        + "."
        + b64(
            json.dumps({"iss": ISS, "aud": AUD, "iat": now, "exp": now + 60, "jti": "b"}).encode()
        )
    )
    sig = hmac.new(pub.read_bytes(), signing_input.encode(), hashlib.sha256).digest()
    with pytest.raises(TokenRejected):
        v.validate(f"{signing_input}.{b64(sig)}")


# ---------- HTTP app ----------

_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "0"},
    },
}
_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def _app() -> Any:
    def _unconfigured() -> Any:
        raise AuthError("Missing required Azure credential environment variables")

    server = build_server(TokenManager(LazyCredentialProvider(_unconfigured)))
    return build_http_app(server, _validator(), HttpSettings())


def _sse_json(body: str) -> dict[str, Any]:
    for line in body.splitlines():
        if line.startswith("data:"):
            parsed: dict[str, Any] = json.loads(line[5:])
            return parsed
    fallback: dict[str, Any] = json.loads(body)
    return fallback


def test_http_rejects_unauthenticated_and_does_not_echo_token(audit_lines: list[str]) -> None:
    with TestClient(_app(), base_url="http://127.0.0.1:8765") as client:
        resp = client.post("/mcp", json=_INIT, headers=_HEADERS)
        assert resp.status_code == 401
        assert resp.headers["WWW-Authenticate"].startswith("Bearer")
        bad = _token(aud="other")
        resp = client.post(
            "/mcp", json=_INIT, headers={**_HEADERS, "Authorization": f"Bearer {bad}"}
        )
        assert resp.status_code == 401
    err = "\n".join(audit_lines)
    assert "http-auth-rejected" in err
    assert "wrong_audience" in err
    assert bad not in err


def test_http_end_to_end_list_and_call_tools() -> None:
    auth = {**_HEADERS, "Authorization": f"Bearer {_token()}"}
    with TestClient(_app(), base_url="http://127.0.0.1:8765") as client:
        resp = client.post("/mcp", json=_INIT, headers=auth)
        assert resp.status_code == 200, resp.text
        session = resp.headers["mcp-session-id"]
        assert (
            _sse_json(resp.text)["result"]["serverInfo"]["name"] == "mcp-sentinel-detection-engine"
        )
        auth["mcp-session-id"] = session
        client.post(
            "/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=auth
        )
        resp = client.post(
            "/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=auth
        )
        names = {t["name"] for t in _sse_json(resp.text)["result"]["tools"]}
        assert "convert_sigma_to_kql" in names
        resp = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "dry_run_kql", "arguments": {"query": "SecurityEvent"}},
            },
            headers=auth,
        )
        result = _sse_json(resp.text)["result"]
        assert result["isError"] is True
        assert result["structuredContent"]["error"]["code"] == "auth_failure"


def test_http_rejects_dns_rebinding_host() -> None:
    auth = {**_HEADERS, "Authorization": f"Bearer {_token()}"}
    with TestClient(_app(), base_url="http://evil.example") as client:
        resp = client.post("/mcp", json=_INIT, headers=auth)
        assert resp.status_code in {400, 421}


def test_settings_loopback_detection() -> None:
    assert HttpSettings(host="127.0.0.1").is_loopback
    assert HttpSettings(host="localhost").is_loopback
    assert not HttpSettings(host="0.0.0.0").is_loopback  # noqa: S104
    assert not HttpSettings(host="gateway.internal").is_loopback


def test_parse_args_defaults_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _parse_args([]).transport == "stdio"
    monkeypatch.setenv("MCP_SENTINEL_TRANSPORT", "http")
    monkeypatch.setenv("MCP_SENTINEL_HTTP_PORT", "9999")
    args = _parse_args([])
    assert (args.transport, args.port) == ("http", 9999)
    assert _parse_args(["--transport", "stdio"]).transport == "stdio"


def test_audit_lines_carry_transport(audit_lines: list[str]) -> None:
    audit_module.set_transport("http")
    try:
        audit_module.audit("probe")
    finally:
        audit_module.set_transport(None)
    assert json.loads(audit_lines[-1])["transport"] == "http"
