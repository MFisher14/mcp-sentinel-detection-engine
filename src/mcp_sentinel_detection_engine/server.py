"""MCP server entry point."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from collections.abc import Awaitable, Callable
from typing import Any

import mcp.types as mcp_types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from . import __version__
from .audit import audit, audit_error, set_transport
from .auth import TokenManager, build_default_token_manager
from .errors import ErrorCode, SentinelError
from .ratelimit import RateLimiter
from .tool_context import ToolContext
from .tools import (
    convert_sigma,
    detect_drift,
    dry_run,
    emit_terraform,
    link_hunt,
    list_rules,
    terraform_plan,
    validate_kql,
)

ServerName = "mcp-sentinel-detection-engine"

_log = logging.getLogger("mcp_sentinel_detection_engine.server")

ToolHandler = Callable[[ToolContext, dict[str, Any]], Awaitable[dict[str, Any]]]


_TOOL_MODULES = (
    convert_sigma,
    validate_kql,
    dry_run,
    emit_terraform,
    list_rules,
    detect_drift,
    terraform_plan,
    link_hunt,
)


def _tool_definitions() -> list[mcp_types.Tool]:
    return [
        mcp_types.Tool(
            name=module.TOOL_NAME,
            description=module.TOOL_DESCRIPTION,
            inputSchema=module.INPUT_SCHEMA,
        )
        for module in _TOOL_MODULES
    ]


_HANDLERS: dict[str, ToolHandler] = {module.TOOL_NAME: module.run for module in _TOOL_MODULES}


def _error_result(code: ErrorCode, message: str) -> mcp_types.CallToolResult:
    payload: dict[str, Any] = {"error": {"code": code.value, "message": message}}
    return mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text=json.dumps(payload))],
        structuredContent=payload,
        isError=True,
    )


def _success_result(data: dict[str, Any]) -> mcp_types.CallToolResult:
    return mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text=json.dumps(data, default=str))],
        structuredContent=data,
        isError=False,
    )


async def _dispatch(
    handler: ToolHandler,
    ctx: ToolContext,
    arguments: dict[str, Any],
    tool_name: str,
) -> mcp_types.CallToolResult:
    try:
        data = await handler(ctx, arguments)
    except SentinelError as exc:
        audit_error(
            "tool-error-mapped",
            tool=tool_name,
            error_code=exc.code.value,
            error_class=exc.__class__.__name__,
        )
        return _error_result(exc.code, exc.public_message)
    except Exception as exc:
        audit_error(
            "tool-error-unhandled",
            tool=tool_name,
            error_class=exc.__class__.__name__,
        )
        return _error_result(
            ErrorCode.INTERNAL_ERROR,
            "An internal error occurred; check server logs for details.",
        )
    return _success_result(data)


def build_server(token_manager: TokenManager) -> Server:
    server: Server = Server(ServerName, version=__version__)
    # One limiter for the process lifetime: quotas and breakers must outlive
    # the per-call ToolContext.
    rate_limiter = RateLimiter(token_manager.rate_limit_configs())

    @server.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]
    async def _list_tools() -> list[mcp_types.Tool]:
        return _tool_definitions()

    @server.call_tool()  # type: ignore[untyped-decorator]
    async def _call_tool(name: str, arguments: dict[str, Any]) -> mcp_types.CallToolResult:
        handler = _HANDLERS.get(name)
        if handler is None:
            audit_error("tool-unknown", tool=name)
            return _error_result(ErrorCode.INVALID_INPUT, f"Unknown tool: {name}")
        async with ToolContext(token_manager, rate_limiter=rate_limiter) as ctx:
            return await _dispatch(handler, ctx, arguments, name)

    return server


TRANSPORTS = ("stdio", "http")


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    env = os.environ
    parser = argparse.ArgumentParser(
        prog="mcp-sentinel-detection-engine",
        description="Sigma → KQL → Sentinel Terraform pipeline as an MCP server.",
    )
    parser.add_argument(
        "--transport",
        choices=TRANSPORTS,
        default=env.get("MCP_SENTINEL_TRANSPORT", "stdio"),
        help="MCP transport (default: stdio; env MCP_SENTINEL_TRANSPORT).",
    )
    parser.add_argument(
        "--host",
        default=env.get("MCP_SENTINEL_HTTP_HOST", "127.0.0.1"),
        help="HTTP bind address (default 127.0.0.1; env MCP_SENTINEL_HTTP_HOST).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(env.get("MCP_SENTINEL_HTTP_PORT", "8765")),
        help="HTTP port (default 8765; env MCP_SENTINEL_HTTP_PORT).",
    )
    args = parser.parse_args(argv)
    if args.transport not in TRANSPORTS:
        parser.error(f"--transport must be one of {', '.join(TRANSPORTS)}")
    return args


async def _async_main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    set_transport(args.transport)
    audit("server-starting", version=__version__)
    try:
        # Credentials are resolved lazily, on the first call that actually
        # needs Azure. An unconfigured host still starts and serves the three
        # pure tools; only dry_run_kql reports the missing configuration.
        token_manager = build_default_token_manager()
        validator = None
        if args.transport == "http":
            from .http_auth import BearerTokenValidator

            validator = BearerTokenValidator.from_env()
    except SentinelError as exc:
        audit_error("server-startup-failed", error_class=exc.__class__.__name__)
        print(f"mcp-sentinel-detection-engine: {exc}", file=sys.stderr)
        sys.exit(2)

    server = build_server(token_manager)
    if validator is not None:
        from .http_transport import HttpSettings, serve_http

        allowed = os.environ.get("MCP_SENTINEL_HTTP_ALLOWED_HOSTS", "")
        settings = HttpSettings(
            host=args.host,
            port=args.port,
            tls_certfile=os.environ.get("MCP_SENTINEL_HTTP_TLS_CERT") or None,
            tls_keyfile=os.environ.get("MCP_SENTINEL_HTTP_TLS_KEY") or None,
            allowed_hosts=tuple(h.strip() for h in allowed.split(",") if h.strip()),
        )
        await serve_http(server, validator, settings)
        return

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main(argv: list[str] | None = None) -> None:
    try:
        asyncio.run(_async_main(argv))
    except KeyboardInterrupt:
        audit("server-interrupted")
    except SystemExit:
        raise
    except Exception as exc:
        audit_error("server-crashed", error_class=exc.__class__.__name__)
        raise


if __name__ == "__main__":
    main()
