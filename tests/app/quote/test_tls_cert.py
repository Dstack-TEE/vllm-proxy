"""Unit tests for the custom-domain SPKI fingerprint helper.

Loads app.quote.tls_cert directly (only cryptography + stdlib) so it runs
without the proxy's GPU / web3 / dstack stack.
"""

import datetime
import importlib.util
import os
import sys
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_SRC = Path(__file__).resolve().parents[3] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
_spec = importlib.util.spec_from_file_location(
    "app_quote_tls_cert", _SRC / "app" / "quote" / "tls_cert.py"
)
tls_cert = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tls_cert)


def _make_cert() -> tuple[bytes, bytes]:
    """Return (PEM, expected SHA256(SPKI DER) bytes) for a fresh EC cert."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2099, 1, 1))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem, sha256(spki).digest()


class TestTlsCert(unittest.TestCase):
    def setUp(self):
        tls_cert._cache.update(path=None, mtime=None, digest=None)
        os.environ.pop(tls_cert.TLS_CERT_PATH_ENV, None)

    def tearDown(self):
        os.environ.pop(tls_cert.TLS_CERT_PATH_ENV, None)

    def _write(self, pem: bytes) -> str:
        fd, name = tempfile.mkstemp(suffix=".pem")
        os.close(fd)
        self.addCleanup(lambda: os.path.exists(name) and os.unlink(name))
        Path(name).write_bytes(pem)
        return name

    def test_spki_digest_matches(self):
        pem, expected = _make_cert()
        self.assertEqual(tls_cert.spki_sha256_from_pem(pem), expected)

    def test_leaf_selected_from_fullchain(self):
        leaf, expected = _make_cert()
        other, _ = _make_cert()
        self.assertEqual(tls_cert.spki_sha256_from_pem(leaf + other), expected)

    def test_resolve_from_env(self):
        pem, expected = _make_cert()
        os.environ[tls_cert.TLS_CERT_PATH_ENV] = self._write(pem)
        self.assertEqual(tls_cert.resolve_spki_fingerprint(), expected)

    def test_resolve_unset_or_missing(self):
        self.assertIsNone(tls_cert.resolve_spki_fingerprint())
        os.environ[tls_cert.TLS_CERT_PATH_ENV] = "/no/such/cert.pem"
        self.assertIsNone(tls_cert.resolve_spki_fingerprint())

    def test_mtime_cache_recomputes(self):
        pem1, exp1 = _make_cert()
        path = self._write(pem1)
        os.environ[tls_cert.TLS_CERT_PATH_ENV] = path
        self.assertEqual(tls_cert.resolve_spki_fingerprint(), exp1)

        pem2, exp2 = _make_cert()
        self.assertNotEqual(exp1, exp2)
        Path(path).write_bytes(pem2)
        os.utime(path, (os.stat(path).st_atime, os.stat(path).st_mtime + 10))
        self.assertEqual(tls_cert.resolve_spki_fingerprint(), exp2)


if __name__ == "__main__":
    unittest.main()
