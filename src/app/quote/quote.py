import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import web3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dstack_sdk import DstackClient
from eth_account.messages import encode_defunct

ED25519 = "ed25519"
ECDSA = "ecdsa"
GPU_ARCH = "HOPPER"


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _gpu_evidence_python() -> str:
    return os.getenv("GPU_EVIDENCE_PYTHON", "").strip()


def _gpu_evidence_timeout_seconds() -> float:
    raw_value = os.getenv("GPU_EVIDENCE_TIMEOUT_SECONDS", "60").strip()
    try:
        return float(raw_value)
    except ValueError:
        return 60.0


def _truncate(text: str, limit: int = 1500) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"... (truncated, total {len(text)} chars)"


def _validate_gpu_evidence(payload: object) -> list[dict[str, str]]:
    if not isinstance(payload, list):
        raise RuntimeError(f"GPU evidence must be a list, got {type(payload).__name__}")
    if not payload:
        raise RuntimeError("GPU evidence list is empty")

    validated: list[dict[str, str]] = []
    for idx, item in enumerate(payload):
        if not isinstance(item, dict):
            raise RuntimeError(
                f"GPU evidence item at index {idx} must be an object, got {type(item).__name__}"
            )

        missing_keys = [k for k in ("certificate", "evidence", "arch") if k not in item]
        if missing_keys:
            raise RuntimeError(
                f"GPU evidence item at index {idx} missing keys: {', '.join(missing_keys)}"
            )

        certificate = item.get("certificate")
        evidence = item.get("evidence")
        arch = item.get("arch")
        if not isinstance(certificate, str) or not certificate:
            raise RuntimeError(f"GPU evidence item at index {idx} has empty certificate")
        if not isinstance(evidence, str) or not evidence:
            raise RuntimeError(f"GPU evidence item at index {idx} has empty evidence")
        if not isinstance(arch, str) or not arch:
            raise RuntimeError(f"GPU evidence item at index {idx} has empty arch")

        validated.append({"certificate": certificate, "evidence": evidence, "arch": arch})
    return validated


@dataclass
class SigningContext:
    method: str
    signing_address: str
    signing_address_bytes: bytes
    _ed_private: Optional[Ed25519PrivateKey] = None
    _raw_account: Optional[web3.Account] = None

    def sign(self, content: str) -> str:
        if self.method == ED25519 and self._ed_private:
            signature = self._ed_private.sign(content.encode("utf-8"))
            return signature.hex()
        if self.method == ECDSA and self._raw_account:
            signed_message = self._raw_account.sign_message(encode_defunct(text=content))
            return f"0x{signed_message.signature.hex()}"
        raise ValueError("Signing context is not properly initialised")


def _build_report_data(signing_address_bytes: bytes, nonce: bytes) -> bytes:
    """Build TDX report data: [signing_address (padded to 32 bytes) || nonce (32 bytes)]"""
    if not signing_address_bytes:
        raise ValueError("Signing address must be provided")
    if len(signing_address_bytes) > 32:
        raise ValueError("Signing address exceeds 32 bytes")
    if len(nonce) != 32:
        raise ValueError("Nonce must be 32 bytes")
    return signing_address_bytes.ljust(32, b"\x00") + nonce


def _parse_nonce(nonce: Optional[bytes | str]) -> bytes:
    if nonce is None:
        return os.urandom(32)
    if isinstance(nonce, bytes):
        nonce_bytes = nonce
    else:
        try:
            nonce_bytes = bytes.fromhex(nonce)
        except ValueError as exc:
            raise ValueError("Nonce must be hex-encoded") from exc
    if len(nonce_bytes) != 32:
        raise ValueError("Nonce must be 32 bytes")
    return nonce_bytes


def _collect_gpu_evidence(nonce_hex: str, no_gpu_mode: bool) -> list:
    gpu_evidence_python = _gpu_evidence_python()
    if gpu_evidence_python:
        script_path = Path(__file__).with_name("ppcie_collect.py")
        cmd = [gpu_evidence_python, str(script_path), "--nonce", nonce_hex, "--ppcie-mode"]
        if no_gpu_mode:
            cmd.append("--no-gpu-mode")

        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=_gpu_evidence_timeout_seconds(),
            )
        except FileNotFoundError as error:
            raise RuntimeError(
                f"GPU evidence Python interpreter not found: {gpu_evidence_python}"
            ) from error
        except subprocess.CalledProcessError as error:
            raise RuntimeError(
                "GPU evidence subprocess failed. "
                f"exit={error.returncode} stdout={_truncate(error.stdout or '')!r} "
                f"stderr={_truncate(error.stderr or '')!r}"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                f"GPU evidence subprocess timed out after {error.timeout}s"
            ) from error
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                "GPU evidence subprocess returned invalid JSON (stdout must be JSON only). "
                f"stdout={_truncate(result.stdout)!r} stderr={_truncate(result.stderr)!r}"
            ) from error
        try:
            return _validate_gpu_evidence(payload)
        except RuntimeError as error:
            raise RuntimeError(
                "GPU evidence subprocess returned invalid evidence shape. "
                f"error={error} stdout={_truncate(result.stdout)!r} stderr={_truncate(result.stderr)!r}"
            ) from error

    try:
        from verifier import cc_admin
    except ImportError as error:
        raise RuntimeError(
            "nv-ppcie-verifier is required for GPU evidence collection; either run the GPU-enabled "
            "image or set GPU_EVIDENCE_PYTHON to a Python interpreter with nv-ppcie-verifier installed"
        ) from error

    try:
        payload = cc_admin.collect_gpu_evidence_remote(
            nonce_hex, no_gpu_mode=no_gpu_mode, ppcie_mode=True
        )
    except Exception as error:
        raise RuntimeError(f"GPU evidence collection failed: {error}") from error

    return _validate_gpu_evidence(payload)


def _build_nvidia_payload(nonce_hex: str, evidences: list) -> str:
    data = {"nonce": nonce_hex, "evidence_list": evidences, "arch": GPU_ARCH}
    return json.dumps(data)


def _create_ed25519_context() -> SigningContext:
    private_key = Ed25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signing_address = public_key_bytes.hex()
    return SigningContext(
        method=ED25519,
        signing_address=signing_address,
        signing_address_bytes=public_key_bytes,
        _ed_private=private_key,
    )


def _create_ecdsa_context() -> SigningContext:
    w3 = web3.Web3()
    account = w3.eth.account.create()
    signing_address = account.address
    # Use the 20-byte Ethereum address for attestation (standard verification identifier)
    address_bytes = bytes.fromhex(signing_address[2:])  # Remove '0x' prefix
    return SigningContext(
        method=ECDSA,
        signing_address=signing_address,
        signing_address_bytes=address_bytes,
        _raw_account=account,
    )


ecdsa_context = _create_ecdsa_context()
ed25519_context = _create_ed25519_context()


def sign_message(context: SigningContext, content: str) -> str:
    return context.sign(content)


def generate_attestation(
    context: SigningContext, nonce: Optional[bytes | str] = None
) -> dict:
    request_nonce_bytes = _parse_nonce(nonce)
    request_nonce_hex = request_nonce_bytes.hex()

    # Build TDX report data: signing_address || request_nonce
    report_data = _build_report_data(context.signing_address_bytes, request_nonce_bytes)

    client = DstackClient()
    quote_result = client.get_quote(report_data)

    # Use request_nonce directly for GPU attestation
    gpu_evidence = _collect_gpu_evidence(request_nonce_hex, _bool_env("GPU_NO_HW_MODE", False))
    if not gpu_evidence:
        raise Exception("No GPU evidence found")
    nvidia_payload = _build_nvidia_payload(request_nonce_hex, gpu_evidence)

    info = client.info().model_dump()

    return dict(
        signing_address=context.signing_address,
        signing_algo=context.method,
        request_nonce=request_nonce_hex,
        intel_quote=quote_result.quote,
        nvidia_payload=nvidia_payload,
        info=info,
        quote=quote_result.quote,
        event_log=quote_result.event_log,
        vm_config=quote_result.vm_config,
    )


__all__ = [
    "SigningContext",
    "sign_message",
    "generate_attestation",
    "ecdsa_context",
    "ed25519_context",
    "ED25519",
    "ECDSA",
]
