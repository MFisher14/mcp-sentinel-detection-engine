"""Streamable HTTP (with SSE response streams) transport for remote MCP clients.

stdio remains the default transport. This module is only used when the
server is started with ``--transport http`` / ``MCP_SENTINEL_TRANSPORT=http``.
Every request is authenticated by :class:`~.http_auth.BearerTokenValidator`
before it reaches the MCP session manager; there is no unauthenticated mode.
"""

from __future__ import annotations

import contextlib
import ipaddress
from collections.abc import AsyncIterator
from dataclasses import dataclass

from mcp.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from .audit import audit, audit_error
from .http_auth import BearerTokenValidator, TokenRejected

MCP_PATH = "/mcp"


@dataclass(frozen=True)
class HttpSettings:
    host: str = "127.0.0.1"
    port: int = 8765
    tls_certfile: str | None = None
    tls_keyfile: str | None = None
    allowed_hosts: tuple[str, ...] = ()

    @property
    def is_loopback(self) -> bool:
        if self.host == "localhost":
            return True
        try:
            return ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            return False


class BearerAuthMiddleware:
    """Reject any HTTP request without a valid bearer token."""

    def __init__(self, app: ASGIApp, validator: BearerTokenValidator) -> None:
        self._app = app
        self._validator = validator

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        header: str | None = None
        for name, value in scope.get("headers", []):
            if name == b"authorization":
                header = value.decode("latin-1")
                break
        client = scope.get("client")
        try:
            claims = self._validator.validate_header(header)
        except TokenRejected as exc:
            audit_error(
                "http-auth-rejected",
                reason=exc.reason,
                path=scope.get("path"),
                client_host=client[0] if client else None,
            )
            response = JSONResponse(
                {"error": {"code": "auth_failure", "message": "Unauthorized"}},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
            await response(scope, receive, send)
            return
        audit("http-auth-accepted", subject=claims.get("sub"), path=scope.get("path"))
        await self._app(scope, receive, send)


def build_http_app(
    server: Server, validator: BearerTokenValidator, settings: HttpSettings
) -> Starlette:
    allowed_hosts = list(settings.allowed_hosts) or [
        f"{settings.host}:*",
        "127.0.0.1:*",
        "localhost:*",
    ]
    session_manager = StreamableHTTPSessionManager(
        app=server,
        security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=[],
        ),
    )

    async def handle_mcp(scope: Scope, receive: Receive, send: Send) -> None:
        await session_manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        del app
        async with session_manager.run():
            yield

    return Starlette(
        routes=[Route(MCP_PATH, endpoint=BearerAuthMiddleware(handle_mcp, validator))],
        lifespan=lifespan,
    )


async def serve_http(
    server: Server, validator: BearerTokenValidator, settings: HttpSettings
) -> None:
    import uvicorn

    if not settings.is_loopback and not settings.tls_certfile:
        audit_error(
            "http-transport-plaintext-non-loopback",
            host=settings.host,
            advice="terminate TLS in front of the server or set MCP_SENTINEL_HTTP_TLS_CERT/KEY",
        )
    app = build_http_app(server, validator, settings)
    config = uvicorn.Config(
        app,
        host=settings.host,
        port=settings.port,
        log_level="warning",
        access_log=False,
        ssl_certfile=settings.tls_certfile,
        ssl_keyfile=settings.tls_keyfile,
    )
    audit(
        "http-transport-listening",
        host=settings.host,
        port=settings.port,
        path=MCP_PATH,
        tls=settings.tls_certfile is not None,
    )
    await uvicorn.Server(config).serve()
