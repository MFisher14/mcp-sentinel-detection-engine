"""Structured error types returned by tools."""

from __future__ import annotations

from enum import StrEnum


class ErrorCode(StrEnum):
    AUTH_FAILURE = "auth_failure"
    INVALID_INPUT = "invalid_input"
    UPSTREAM_ERROR = "upstream_error"
    RATE_LIMITED = "rate_limited"
    NOT_FOUND = "not_found"
    CONVERSION_ERROR = "conversion_error"
    SCHEMA_VALIDATION_ERROR = "schema_validation_error"
    INTERNAL_ERROR = "internal_error"


class SentinelError(Exception):
    """Base class for errors that should be surfaced to MCP clients."""

    code: ErrorCode = ErrorCode.INTERNAL_ERROR

    def __init__(self, message: str, *, code: ErrorCode | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code

    @property
    def public_message(self) -> str:
        return str(self)


class AuthError(SentinelError):
    code = ErrorCode.AUTH_FAILURE


class InvalidInputError(SentinelError):
    code = ErrorCode.INVALID_INPUT


class ConversionError(SentinelError):
    code = ErrorCode.CONVERSION_ERROR


class SchemaValidationError(SentinelError):
    code = ErrorCode.SCHEMA_VALIDATION_ERROR


class UpstreamError(SentinelError):
    code = ErrorCode.UPSTREAM_ERROR

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class RateLimitedError(UpstreamError):
    code = ErrorCode.RATE_LIMITED


class NotFoundError(UpstreamError):
    code = ErrorCode.NOT_FOUND
