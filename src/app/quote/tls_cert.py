"""SPKI fingerprint of the custom-domain TLS cert, bound into report_data for attestation v2."""

import os
from hashlib import sha256
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

TLS_CERT_PATH_ENV = "TLS_CERT_PATH"

_cache: dict = {"path": None, "mtime": None, "digest": None}


def spki_sha256_from_pem(pem: bytes) -> bytes:
    """SHA256 of the leaf certificate's SubjectPublicKeyInfo."""
    cert = x509.load_pem_x509_certificate(pem)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return sha256(spki).digest()


def resolve_spki_fingerprint() -> Optional[bytes]:
    """Fingerprint of the cert at $TLS_CERT_PATH, cached by mtime. None if unset or unreadable."""
    path = os.getenv(TLS_CERT_PATH_ENV)
    if not path:
        return None
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        return None
    if _cache["path"] == path and _cache["mtime"] == mtime:
        return _cache["digest"]
    try:
        with open(path, "rb") as f:
            digest = spki_sha256_from_pem(f.read())
    except Exception:
        return None
    _cache.update(path=path, mtime=mtime, digest=digest)
    return digest
