"""Pluggable secret-store backends that materialize App Registration certificates.

Each backend implements :class:`PfxSource`: given its own parsed configuration,
it returns the raw PFX (PKCS#12) bytes for one tenant. The
:class:`~mcp_sentinel_detection_engine.auth.CredentialProvider` that owns the
tenant exposes those bytes through ``get_pfx_bytes`` and the
:class:`~mcp_sentinel_detection_engine.auth.TokenManager` hands them to MSAL
without the certificate ever touching the host filesystem.

This package must not import :mod:`mcp_sentinel_detection_engine.auth` — the
dependency points the other way.
"""

from __future__ import annotations

from .base import CachingPfxSource, PfxSource
from .pfx import load_pfx, normalize_pfx, pfx_to_msal_credential

__all__ = [
    "CachingPfxSource",
    "PfxSource",
    "load_pfx",
    "normalize_pfx",
    "pfx_to_msal_credential",
]
