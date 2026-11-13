"""mcp-sentinel-detection-engine — Sigma → KQL → Sentinel Terraform pipeline as MCP tools."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

#: Distribution name as declared in pyproject.toml. The installed distribution's
#: metadata is the single source of truth for the version, so the number lives in
#: exactly one place and cannot drift from the package it ships in.
_DISTRIBUTION_NAME = "mcp-sentinel-detection-engine"

#: Reported when the distribution metadata cannot be found — i.e. the package is
#: being imported straight from a source checkout that was never installed (no
#: `pip install -e .`), typically a PYTHONPATH-style run. A regular editable
#: install does have metadata and reports the real version. The marker is a valid
#: PEP 440 local version, so it stays parseable rather than blowing up a caller
#: that tries to compare it.
_UNINSTALLED_VERSION = "0.0.0+unknown"


def _detect_version() -> str:
    """Resolve the running version from installed distribution metadata."""
    try:
        return version(_DISTRIBUTION_NAME)
    except PackageNotFoundError:
        return _UNINSTALLED_VERSION


__version__ = _detect_version()

__all__ = ["__version__"]
