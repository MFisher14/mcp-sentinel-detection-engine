"""Tests for the HashiCorp Vault PFX source (issue #11). No network."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

from mcp_sentinel_detection_engine.auth import JsonFileCredentialProvider
from mcp_sentinel_detection_engine.credentials import base as cred_base
from mcp_sentinel_detection_engine.credentials import load_pfx
from mcp_sentinel_detection_engine.credentials.hashicorp_vault import (
    VaultPfxSource,
    parse_vault_block,
)
from mcp_sentinel_detection_engine.errors import AuthError

from ._pfx_factory import make_pfx

_ADDR = "https://vault.example.com:8200"
_GUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


class FakeVault:
    """In-memory Vault that records requests and serves KV-v2 + auth endpoints."""

    def __init__(
        self,
        *,
        pfx: bytes,
        passphrase: str | None = None,
        lease: int = 3600,
        renewable: bool = True,
        lookup_ttl: int = 3600,
    ) -> None:
        secret: dict[str, Any] = {"pfx_base64": base64.b64encode(pfx).decode()}
        if passphrase is not None:
            secret["passphrase"] = passphrase
        self.secret = secret
        self.lease = lease
        self.renewable = renewable
        self.lookup_ttl = lookup_ttl
        self.requests: list[httpx.Request] = []
        self.valid_tokens = {"static-token"}
        self.read_status = 200
        self.counter = 0

    def _issue(self) -> dict[str, Any]:
        self.counter += 1
        token = f"issued-{self.counter}"
        self.valid_tokens.add(token)
        return {
            "auth": {
                "client_token": token,
                "lease_duration": self.lease,
                "renewable": self.renewable,
            }
        }

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        token = request.headers.get("X-Vault-Token")
        if path.endswith("/login"):
            return httpx.Response(200, json=self._issue())
        if path == "/v1/sys/wrapping/unwrap":
            if token != "wrapped-token":
                return httpx.Response(400, json={"errors": ["wrapping token is not valid"]})
            return httpx.Response(200, json=self._issue())
        if token not in self.valid_tokens:
            return httpx.Response(403, json={"errors": ["permission denied"]})
        if path == "/v1/auth/token/lookup-self":
            return httpx.Response(
                200, json={"data": {"ttl": self.lookup_ttl, "renewable": self.renewable}}
            )
        if path == "/v1/auth/token/renew-self":
            return httpx.Response(
                200,
                json={
                    "auth": {
                        "client_token": token,
                        "lease_duration": self.lease,
                        "renewable": self.renewable,
                    }
                },
            )
        if path == "/v1/secret/data/mcp/contoso":
            if self.read_status != 200:
                return httpx.Response(self.read_status, json={"errors": []})
            return httpx.Response(200, json={"data": {"data": self.secret, "metadata": {}}})
        return httpx.Response(404, json={"errors": []})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))

    def paths(self) -> list[str]:
        return [r.url.path for r in self.requests]


def _block(auth: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"address": _ADDR, "mount": "secret", "path": "mcp/contoso", "auth": auth, **extra}


def _source(
    vault: FakeVault,
    auth: dict[str, Any],
    env: dict[str, str] | None = None,
    *,
    clock: list[float] | None = None,
    **extra: Any,
) -> VaultPfxSource:
    times = clock if clock is not None else [1000.0]
    return parse_vault_block(
        "contoso",
        _block(auth, **extra),
        env or {},
        http_client=vault.client(),
        time_source=lambda: times[0],
    )


def test_static_token_reads_kv_v2_secret() -> None:
    pfx = make_pfx()
    vault = FakeVault(pfx=pfx)
    source = _source(
        vault, {"method": "token", "token_env": "VAULT_TOKEN"}, {"VAULT_TOKEN": "static-token"}
    )
    assert source.fetch_pfx() == pfx
    assert vault.paths() == ["/v1/auth/token/lookup-self", "/v1/secret/data/mcp/contoso"]
    assert vault.requests[-1].headers["X-Vault-Token"] == "static-token"


def test_passphrase_in_secret_is_applied() -> None:
    vault = FakeVault(pfx=make_pfx("pw"), passphrase="pw")
    source = _source(vault, {"method": "token", "token_env": "T"}, {"T": "static-token"})
    load_pfx(source.fetch_pfx(), None)


def test_namespace_header() -> None:
    vault = FakeVault(pfx=make_pfx())
    source = _source(
        vault, {"method": "token", "token_env": "T"}, {"T": "static-token"}, namespace="team/a"
    )
    source.fetch_pfx()
    assert all(r.headers["X-Vault-Namespace"] == "team/a" for r in vault.requests)


def test_wrapped_token_is_unwrapped_once() -> None:
    vault = FakeVault(pfx=make_pfx())
    source = _source(
        vault, {"method": "token", "token_env": "T", "wrapped": True}, {"T": "wrapped-token"}
    )
    source.fetch_pfx()
    source.fetch_pfx()
    assert vault.paths().count("/v1/sys/wrapping/unwrap") == 1
    assert vault.requests[-1].headers["X-Vault-Token"] == "issued-1"


def test_approle_login() -> None:
    vault = FakeVault(pfx=make_pfx())
    source = _source(
        vault,
        {"method": "approle", "role_id_env": "RID", "secret_id_env": "SID"},
        {"RID": "r", "SID": "s"},
    )
    source.fetch_pfx()
    login = vault.requests[0]
    assert login.url.path == "/v1/auth/approle/login"
    assert json.loads(login.content) == {"role_id": "r", "secret_id": "s"}


def test_kubernetes_login(tmp_path: Path) -> None:
    jwt = tmp_path / "token"
    jwt.write_text("k8s-jwt\n")
    vault = FakeVault(pfx=make_pfx())
    source = _source(
        vault,
        {"method": "kubernetes", "role": "mcp", "jwt_path": str(jwt), "mount": "k8s-prod"},
    )
    source.fetch_pfx()
    login = vault.requests[0]
    assert login.url.path == "/v1/auth/k8s-prod/login"
    assert json.loads(login.content) == {"role": "mcp", "jwt": "k8s-jwt"}


@pytest.mark.parametrize("content", [None, ""])
def test_kubernetes_jwt_unreadable_or_empty(tmp_path: Path, content: str | None) -> None:
    jwt = tmp_path / "token"
    if content is not None:
        jwt.write_text(content)
    source = _source(
        FakeVault(pfx=make_pfx()), {"method": "kubernetes", "role": "mcp", "jwt_path": str(jwt)}
    )
    with pytest.raises(AuthError) as exc_info:
        source.fetch_pfx()
    assert str(jwt) not in str(exc_info.value)


def test_token_renewed_when_ttl_below_leeway() -> None:
    clock = [1000.0]
    vault = FakeVault(pfx=make_pfx(), lease=120)
    source = _source(
        vault,
        {"method": "approle", "role_id_env": "R", "secret_id_env": "S"},
        {"R": "r", "S": "s"},
        clock=clock,
    )
    source.fetch_pfx()
    clock[0] += 30  # 90s left: still fresh
    source.fetch_pfx()
    assert "/v1/auth/token/renew-self" not in vault.paths()
    clock[0] += 40  # 50s left: under the 60s leeway
    source.fetch_pfx()
    assert vault.paths().count("/v1/auth/token/renew-self") == 1
    assert vault.paths().count("/v1/auth/approle/login") == 1


def test_non_renewable_token_relogs_in() -> None:
    clock = [1000.0]
    vault = FakeVault(pfx=make_pfx(), lease=120, renewable=False)
    source = _source(
        vault,
        {"method": "approle", "role_id_env": "R", "secret_id_env": "S"},
        {"R": "r", "S": "s"},
        clock=clock,
    )
    source.fetch_pfx()
    clock[0] += 100
    source.fetch_pfx()
    assert vault.paths().count("/v1/auth/approle/login") == 2
    assert "/v1/auth/token/renew-self" not in vault.paths()


def test_static_non_renewable_token_is_used_until_rejected() -> None:
    clock = [1000.0]
    vault = FakeVault(pfx=make_pfx(), renewable=False, lookup_ttl=90)
    source = _source(
        vault, {"method": "token", "token_env": "T"}, {"T": "static-token"}, clock=clock
    )
    source.fetch_pfx()
    clock[0] += 60
    source.fetch_pfx()  # near expiry, not renewable, cannot relogin: still tried
    assert vault.paths().count("/v1/secret/data/mcp/contoso") == 2


def test_root_token_ttl_zero_never_renews() -> None:
    clock = [1000.0]
    vault = FakeVault(pfx=make_pfx(), lookup_ttl=0)
    source = _source(
        vault, {"method": "token", "token_env": "T"}, {"T": "static-token"}, clock=clock
    )
    source.fetch_pfx()
    clock[0] += 10**9
    source.fetch_pfx()
    assert "/v1/auth/token/renew-self" not in vault.paths()


def test_revoked_token_triggers_one_relogin() -> None:
    vault = FakeVault(pfx=make_pfx())
    source = _source(
        vault,
        {"method": "approle", "role_id_env": "R", "secret_id_env": "S"},
        {"R": "r", "S": "s"},
    )
    source.fetch_pfx()
    vault.valid_tokens.clear()  # revoke out-of-band
    source.fetch_pfx()
    assert vault.paths().count("/v1/auth/approle/login") == 2


@pytest.mark.parametrize("status", [403, 404, 500])
def test_read_errors_do_not_echo_path_or_token_source(status: int) -> None:
    vault = FakeVault(pfx=make_pfx())
    vault.read_status = status
    source = _source(
        vault,
        {"method": "token", "token_env": "MY_VAULT_TOKEN"},
        {"MY_VAULT_TOKEN": "static-token"},
    )
    with pytest.raises(AuthError) as exc_info:
        source.fetch_pfx()
    message = str(exc_info.value)
    assert str(status) in message
    for leaked in ("mcp/contoso", "vault.example.com", "MY_VAULT_TOKEN", "static-token"):
        assert leaked not in message


def test_missing_token_env_does_not_echo_name() -> None:
    source = _source(FakeVault(pfx=make_pfx()), {"method": "token", "token_env": "MY_VAULT_TOKEN"})
    with pytest.raises(AuthError) as exc_info:
        source.fetch_pfx()
    assert "MY_VAULT_TOKEN" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("secret", "match"),
    [
        ({"other": "x"}, "pfx_base64"),
        ({"pfx_base64": "!!!"}, "not base64"),
        ({"pfx_base64": "QQ==", "passphrase": 5}, "passphrase"),
    ],
)
def test_bad_secret_shapes(secret: dict[str, Any], match: str) -> None:
    vault = FakeVault(pfx=make_pfx())
    vault.secret = secret
    source = _source(vault, {"method": "token", "token_env": "T"}, {"T": "static-token"})
    with pytest.raises(AuthError, match=match):
        source.fetch_pfx()


def test_network_and_malformed_responses() -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    def garbage(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>")

    def no_token(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"auth": None})

    for handler, match in ((down, "network"), (garbage, "malformed"), (no_token, "no client")):
        source = parse_vault_block(
            "c",
            _block({"method": "approle", "role_id_env": "R", "secret_id_env": "S"}),
            {"R": "r", "S": "s"},
            http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        with pytest.raises(AuthError, match=match):
            source.fetch_pfx()


def test_localhost_http_allowed_for_dev() -> None:
    parse_vault_block(
        "c",
        {**_block({"method": "token", "token_env": "T"}), "address": "http://127.0.0.1:8200"},
        {},
        http_client=FakeVault(pfx=b"").client(),
    )


@pytest.mark.parametrize(
    ("block", "match"),
    [
        (
            {
                **_block({"method": "token", "token_env": "T"}),
                "address": "http://vault.example.com",
            },
            "https",
        ),
        (
            {**_block({"method": "token", "token_env": "T"}), "address": "https://v.example.com/x"},
            "path",
        ),
        (
            {
                **_block({"method": "token", "token_env": "T"}),
                "address": "https://u:p@v.example.com",
            },
            "bare",
        ),
        ({**_block({"method": "token", "token_env": "T"}), "path": "../etc"}, "segments"),
        ({**_block({"method": "token", "token_env": "T"}), "mount": "a b"}, "segments"),
        ({**_block({"method": "token", "token_env": "T"}), "extra": 1}, "unknown fields"),
        (_block("nope"), "must be an object"),  # type: ignore[arg-type]
        (_block({"method": "ldap"}), "method must be"),
        (_block({"method": "token"}), "token_env"),
        (_block({"method": "token", "token_env": "T", "wrapped": "yes"}), "boolean"),
        (_block({"method": "token", "token_env": "T", "x": 1}), "unknown fields"),
        (_block({"method": "approle", "role_id_env": "R"}), "secret_id_env"),
        (_block({"method": "kubernetes"}), "role"),
        (_block({"method": "kubernetes", "role": "a/b"}), "role must"),
    ],
)
def test_parse_vault_block_rejects(block: dict[str, Any], match: str) -> None:
    with pytest.raises(AuthError, match=match):
        parse_vault_block("c", block, {}, http_client=FakeVault(pfx=b"").client())


def test_tenants_json_vault_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pfx = make_pfx()
    vault = FakeVault(pfx=pfx)
    monkeypatch.setattr(cred_base, "new_http_client", vault.client)
    path = tmp_path / "tenants.json"
    path.write_text(
        json.dumps(
            {
                "default": "contoso",
                "tenants": {
                    "contoso": {
                        "tenant_id": "t",
                        "client_id": "c",
                        "workspace_id": _GUID,
                        "vault": _block({"method": "token", "token_env": "VAULT_TOKEN"}),
                    }
                },
            }
        )
    )
    os.chmod(path, 0o600)
    provider = JsonFileCredentialProvider(path, env={"VAULT_TOKEN": "static-token"})
    assert provider.get_credentials().cert_path is None
    assert provider.get_pfx_bytes() == pfx
    assert provider.get_pfx_bytes() == pfx  # cached
    assert vault.paths().count("/v1/secret/data/mcp/contoso") == 1
