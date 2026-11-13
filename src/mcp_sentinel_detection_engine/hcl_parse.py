"""Strict parser for the HCL subset :mod:`terraform_emit` produces.

This is deliberately *not* a general HCL parser. It accepts only:

- top-level ``resource "azurerm_sentinel_alert_rule_scheduled" "<name>" { ... }``
  blocks (other top-level constructs are rejected),
- ``key = value`` attribute lines inside those blocks, where ``value`` is a
  double-quoted string, ``true`` / ``false``, an integer, a single-line list
  of double-quoted strings, a ``<<-MARKER`` / ``<<MARKER`` heredoc, or the
  single variable reference ``var.log_analytics_workspace_id``,
- blank lines and ``#`` / ``//`` comment lines.

Nested blocks (``provisioner``, ``lifecycle``, ``connection``, ``dynamic``,
...), function calls, template interpolation (``${...}``) and template
directives (``%{...}``) are all rejected. That makes the parser double as an
allowlist validator for :mod:`terraform_runner` — anything it accepts is
inert data that can only describe a scheduled analytics rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .errors import InvalidInputError

ALLOWED_RESOURCE_TYPE = "azurerm_sentinel_alert_rule_scheduled"
ALLOWED_VARIABLE_REFS = frozenset({"var.log_analytics_workspace_id"})
MAX_HCL_LENGTH = 200_000

_RESOURCE_HEAD_RE = re.compile(r'^resource\s+"([^"]+)"\s+"([A-Za-z_][A-Za-z0-9_-]{0,255})"\s*\{$')
_ATTR_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
_HEREDOC_RE = re.compile(r"^<<(-?)([A-Za-z_][A-Za-z0-9_]*)$")
_INT_RE = re.compile(r"^-?\d{1,18}$")
# ``${`` / ``%{`` start an interpolation / directive unless escaped as ``$${`` / ``%%{``.
_TEMPLATE_RE = re.compile(r"(?<![$%])[$%]\{")


@dataclass(frozen=True)
class VariableRef:
    """A bare ``var.<name>`` reference (only allowlisted names are accepted)."""

    name: str


@dataclass
class ParsedRule:
    resource_type: str
    resource_name: str
    attributes: dict[str, Any] = field(default_factory=dict)


def _fail(lineno: int, message: str) -> InvalidInputError:
    return InvalidInputError(f"HCL line {lineno}: {message}")


def _check_template(text: str, lineno: int) -> None:
    if _TEMPLATE_RE.search(text):
        raise _fail(lineno, "template interpolation/directives are not allowed")


def _unescape_string(raw: str, lineno: int) -> str:
    out: list[str] = []
    i = 0
    escapes = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
    while i < len(raw):
        ch = raw[i]
        if ch == "\\":
            if i + 1 >= len(raw):
                raise _fail(lineno, "dangling escape in string")
            nxt = raw[i + 1]
            if nxt not in escapes:
                raise _fail(lineno, f"unsupported escape sequence \\{nxt}")
            out.append(escapes[nxt])
            i += 2
            continue
        if ch == '"':
            raise _fail(lineno, "unescaped quote inside string")
        out.append(ch)
        i += 1
    return "".join(out).replace("$${", "${").replace("%%{", "%{")


def _parse_quoted(text: str, lineno: int) -> tuple[str, str]:
    """Parse a leading double-quoted string; return (value, remainder)."""
    if not text.startswith('"'):
        raise _fail(lineno, "expected a double-quoted string")
    i = 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == '"':
            raw = text[1:i]
            _check_template(raw, lineno)
            return _unescape_string(raw, lineno), text[i + 1 :]
        i += 1
    raise _fail(lineno, "unterminated string")


def _parse_list(text: str, lineno: int) -> list[str]:
    inner = text[1:]
    items: list[str] = []
    inner = inner.strip()
    if inner == "]":
        return items
    while True:
        value, rest = _parse_quoted(inner.strip(), lineno)
        items.append(value)
        rest = rest.strip()
        if rest == "]":
            return items
        if not rest.startswith(","):
            raise _fail(lineno, "list items must be double-quoted strings separated by commas")
        inner = rest[1:].strip()
        if inner == "]":  # trailing comma
            return items


def _dedent_heredoc(lines: list[str]) -> str:
    indents = [len(line) - len(line.lstrip(" \t")) for line in lines if line.strip()]
    cut = min(indents) if indents else 0
    return "\n".join(line[cut:] if line.strip() else "" for line in lines)


def _parse_value(text: str, lineno: int) -> Any:
    if text.startswith('"'):
        value, rest = _parse_quoted(text, lineno)
        if rest.strip():
            raise _fail(lineno, "unexpected content after string")
        return value
    if text in {"true", "false"}:
        return text == "true"
    if _INT_RE.match(text):
        return int(text)
    if text.startswith("[") and text.endswith("]"):
        return _parse_list(text, lineno)
    if text in ALLOWED_VARIABLE_REFS:
        return VariableRef(text)
    raise _fail(lineno, "unsupported value (only literals and allowlisted var refs)")


def parse_rules(hcl: str) -> list[ParsedRule]:
    """Parse ``hcl`` into rule blocks, rejecting anything outside the subset."""
    if len(hcl) > MAX_HCL_LENGTH:
        raise InvalidInputError(f"HCL exceeds {MAX_HCL_LENGTH} characters")
    if "\x00" in hcl:
        raise InvalidInputError("HCL must not contain NUL bytes")
    lines = hcl.replace("\r\n", "\n").split("\n")
    rules: list[ParsedRule] = []
    current: ParsedRule | None = None
    i = 0
    while i < len(lines):
        lineno = i + 1
        stripped = lines[i].strip()
        i += 1
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        if current is None:
            head = _RESOURCE_HEAD_RE.match(stripped)
            if head is None:
                raise _fail(
                    lineno,
                    f'only `resource "{ALLOWED_RESOURCE_TYPE}" "<name>" {{` blocks are allowed',
                )
            if head.group(1) != ALLOWED_RESOURCE_TYPE:
                raise _fail(lineno, f"resource type {head.group(1)!r} is not allowed")
            if any(r.resource_name == head.group(2) for r in rules):
                raise _fail(lineno, f"duplicate resource name {head.group(2)!r}")
            current = ParsedRule(head.group(1), head.group(2))
            continue
        if stripped == "}":
            rules.append(current)
            current = None
            continue
        attr = _ATTR_RE.match(stripped)
        if attr is None:
            raise _fail(lineno, "nested blocks and non-attribute statements are not allowed")
        key, raw_value = attr.group(1), attr.group(2).strip()
        if key in current.attributes:
            raise _fail(lineno, f"duplicate attribute {key!r}")
        heredoc = _HEREDOC_RE.match(raw_value)
        if heredoc is not None:
            marker = heredoc.group(2)
            body: list[str] = []
            while True:
                if i >= len(lines):
                    raise _fail(lineno, f"unterminated heredoc {marker}")
                line = lines[i]
                i += 1
                if line.strip() == marker:
                    break
                _check_template(line, i)
                body.append(line)
            text = _dedent_heredoc(body) if heredoc.group(1) == "-" else "\n".join(body)
            current.attributes[key] = text.replace("$${", "${").replace("%%{", "%{")
            continue
        current.attributes[key] = _parse_value(raw_value, lineno)
    if current is not None:
        raise InvalidInputError("HCL ends inside an unterminated resource block")
    if not rules:
        raise InvalidInputError(f"HCL contains no {ALLOWED_RESOURCE_TYPE} resources")
    return rules
