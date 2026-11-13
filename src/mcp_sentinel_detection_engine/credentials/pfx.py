"""PKCS#12 helpers shared by every secret-store backend."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import Certificate

from ..errors import AuthError

# Generic on purpose: never echo where the PFX came from (vault URL, secret
# path, file name) — the message reaches the MCP client.
_INVALID_PFX = "Certificate material could not be loaded (invalid PFX or wrong passphrase)"


def load_pfx(pfx_bytes: bytes, passphrase: str | None) -> tuple[PrivateKeyTypes, Certificate]:
    """Parse PFX bytes, returning ``(private_key, leaf_certificate)``.

    Raises :class:`AuthError` with a source-agnostic message on any failure.
    """
    password = passphrase.encode("utf-8") if passphrase else None
    try:
        key, cert, _ = pkcs12.load_key_and_certificates(pfx_bytes, password)
    except (ValueError, TypeError) as exc:
        raise AuthError(_INVALID_PFX) from exc
    if key is None or cert is None:
        raise AuthError("Certificate material must contain both a private key and a certificate")
    return key, cert


def normalize_pfx(pfx_bytes: bytes, passphrase: str | None) -> bytes:
    """Validate ``pfx_bytes`` and return an *unencrypted* PFX.

    Secret stores may hand back a passphrase alongside the bundle. Decrypting
    once at fetch time keeps the ``get_pfx_bytes`` contract to "bytes only" so
    the passphrase never has to travel through ``AzureCredentials``. The
    result lives only in process memory.
    """
    key, cert = load_pfx(pfx_bytes, passphrase)
    if not passphrase:
        return pfx_bytes
    if not isinstance(key, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey):
        raise AuthError("Certificate private key type is not supported")
    return pkcs12.serialize_key_and_certificates(
        name=None,
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.NoEncryption(),
    )


def pfx_to_msal_credential(pfx_bytes: bytes, passphrase: str | None) -> dict[str, Any]:
    """Convert in-memory PFX bytes into an MSAL ``client_credential`` dict.

    MSAL (as of 1.3x) only accepts a PFX by *path*. For bytes we hand it the
    PEM private key plus the PEM public certificate; MSAL derives the SHA-256 /
    SHA-1 thumbprints and the ``x5c`` header from the certificate.
    """
    key, cert = load_pfx(pfx_bytes, passphrase)
    if not isinstance(key, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey):
        raise AuthError("Certificate private key type is not supported")
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return {"private_key": private_pem, "public_certificate": public_pem}
