"""Version resolution comes from installed distribution metadata."""

from __future__ import annotations

import tomllib
from importlib.metadata import PackageNotFoundError
from pathlib import Path

import pytest

import mcp_sentinel_detection_engine as pkg

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def test_version_is_reported_from_installed_metadata() -> None:
    assert pkg.__version__ == pkg._detect_version()
    assert pkg.__version__ != pkg._UNINSTALLED_VERSION


def test_version_matches_pyproject() -> None:
    """pyproject.toml is the single source of truth; nothing should drift from it."""
    declared = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    assert pkg.__version__ == declared


def test_detect_version_falls_back_when_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    """An uninstalled source checkout has no metadata; importing must not explode."""

    def _raise(_name: str) -> str:
        raise PackageNotFoundError(pkg._DISTRIBUTION_NAME)

    monkeypatch.setattr(pkg, "version", _raise)
    assert pkg._detect_version() == "0.0.0+unknown"


def test_server_reports_the_package_version() -> None:
    """The version the server advertises over MCP is the resolved one."""
    from mcp_sentinel_detection_engine import server

    assert server.__dict__["__version__"] == pkg.__version__
