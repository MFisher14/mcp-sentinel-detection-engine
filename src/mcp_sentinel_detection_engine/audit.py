"""Structured audit logging for tool invocations."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

_LOGGER_NAME = "mcp_sentinel_detection_engine.audit"
_ENV_LEVEL = "MCP_SENTINEL_LOG_LEVEL"


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        extra = getattr(record, "audit_fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
        return json.dumps(payload, separators=(",", ":"), default=str)


def _configure() -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    if getattr(logger, "_mcp_sentinel_configured", False):
        return logger
    logger.setLevel(os.environ.get(_ENV_LEVEL, "INFO").upper())
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(_JsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False
    logger._mcp_sentinel_configured = True  # type: ignore[attr-defined]
    return logger


_logger = _configure()


def audit(event: str, **fields: Any) -> None:
    sanitized = {k: v for k, v in fields.items() if v is not None}
    _logger.info(event, extra={"audit_fields": sanitized})


def audit_error(event: str, **fields: Any) -> None:
    sanitized = {k: v for k, v in fields.items() if v is not None}
    _logger.error(event, extra={"audit_fields": sanitized})


@contextmanager
def audit_tool_call(tool_name: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
    start = time.perf_counter()
    extra: dict[str, Any] = {}
    audit(
        "tool-invoked",
        tool=tool_name,
        params=params,
    )
    try:
        yield extra
    except Exception as exc:
        duration_ms = int((time.perf_counter() - start) * 1000)
        audit_error(
            "tool-failed",
            tool=tool_name,
            duration_ms=duration_ms,
            error_class=exc.__class__.__name__,
            error_message=str(exc),
            **extra,
        )
        raise
    else:
        duration_ms = int((time.perf_counter() - start) * 1000)
        audit(
            "tool-succeeded",
            tool=tool_name,
            duration_ms=duration_ms,
            **extra,
        )
