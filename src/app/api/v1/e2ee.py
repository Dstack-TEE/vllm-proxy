import os
import hashlib
from dataclasses import dataclass
from typing import Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.cache.replay_cache import replay_cache
from app.quote.quote import ECDSA, ED25519, ecdsa_context, ed25519_context

E2EE_VERSION_V1 = "1"
E2EE_VERSION_V2 = "2"
_ECDSA_HKDF_INFO = b"ecdsa_encryption"
_ED25519_HKDF_INFO = b"ed25519_encryption"


class E2EEError(ValueError):
    """Base class for E2EE related errors."""

    def __init__(self, message: str, error_type: str):
        super().__init__(message)
        self.error_type = error_type


class E2EEHeaderMissingError(E2EEError):
    def __init__(self, message: str):
        super().__init__(message, "e2ee_header_missing")


class E2EEInvalidSigningAlgoError(E2EEError):
    def __init__(self, message: str):
        super().__init__(message, "e2ee_invalid_signing_algo")


class E2EEInvalidPublicKeyError(E2EEError):
    def __init__(self, message: str):
        super().__init__(message, "e2ee_invalid_public_key")


class E2EEModelKeyMismatchError(E2EEError):
    def __init__(self, message: str):
        super().__init__(message, "e2ee_model_key_mismatch")


class E2EEInvalidVersionError(E2EEError):
    def __init__(self, message: str):
        super().__init__(message, "e2ee_invalid_version")


class E2EEInvalidNonceError(E2EEError):
    def __init__(self, message: str):
        super().__init__(message, "e2ee_invalid_nonce")


class E2EEReplayDetectedError(E2EEError):
    def __init__(self, message: str):
        super().__init__(message, "e2ee_replay_detected")


class E2EEInvalidTimestampError(E2EEError):
    def __init__(self, message: str):
        super().__init__(message, "e2ee_invalid_timestamp")


class E2EEDecryptionFailedError(E2EEError):
    def __init__(self, message: str):
        super().__init__(message, "e2ee_decryption_failed")


@dataclass
class E2EEContext:
    signing_algo: str
    client_public_key_hex: str
    model_public_key_hex: str
    version: str
    nonce: str | None
    timestamp: int | None
    _ephemeral_public_bytes: bytes | None = None
    _aes_key: bytes | None = None


def _is_hex(value: str) -> bool:
    if not value or len(value) % 2 != 0:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def _to_uncompressed_pubkey_bytes(pub_key_hex: str) -> bytes:
    key_bytes = bytes.fromhex(pub_key_hex)
    if len(key_bytes) == 64:
        return b"\x04" + key_bytes
    if len(key_bytes) == 65 and key_bytes[0] == 0x04:
        return key_bytes
    raise ValueError("Public key must be 64-byte hex or uncompressed 65-byte hex")


def _local_model_private_key(signing_algo: str):
    if signing_algo == ECDSA:
        if ecdsa_context._raw_account is None:
            raise ValueError("ECDSA context not initialized")
        key_int = int.from_bytes(bytes(ecdsa_context._raw_account.key), byteorder="big")
        return ec.derive_private_key(key_int, ec.SECP256K1())

    if signing_algo == ED25519:
        if ed25519_context._ed_private is None:
            raise ValueError("Ed25519 context not initialized")
        return ed25519_context._ed_private

    raise ValueError("Unsupported signing algorithm")


def local_model_public_key_hex(signing_algo: str) -> str:
    private_key = _local_model_private_key(signing_algo)

    if signing_algo == ECDSA:
        pub_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        return pub_bytes[1:].hex()

    if signing_algo == ED25519:
        pub_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return pub_bytes.hex()

    raise ValueError("Unsupported signing algorithm")


def _validate_replay_and_timestamp(nonce: str, timestamp: int, signing_algo: str) -> None:
    if not replay_cache.validate_timestamp_window(timestamp):
        raise E2EEInvalidTimestampError("X-E2EE-Timestamp is outside allowed replay window")

    if not replay_cache.claim(signing_algo=signing_algo, timestamp=timestamp, nonce=nonce):
        raise E2EEReplayDetectedError("Replay detected: duplicated X-E2EE-Nonce/X-E2EE-Timestamp")


def parse_e2ee_context(
    x_signing_algo: str | None,
    x_client_pub_key: str | None,
    x_model_pub_key: str | None,
    x_e2ee_version: str | None = None,
    x_e2ee_nonce: str | None = None,
    x_e2ee_timestamp: str | None = None,
) -> E2EEContext | None:
    headers_present = any([x_signing_algo, x_client_pub_key, x_model_pub_key])
    if not headers_present:
        return None

    if not x_signing_algo or not x_client_pub_key or not x_model_pub_key:
        raise E2EEHeaderMissingError(
            "E2EE requires X-Signing-Algo, X-Client-Pub-Key, and X-Model-Pub-Key headers"
        )

    algo = x_signing_algo.strip().lower()
    if algo not in (ECDSA, ED25519):
        raise E2EEInvalidSigningAlgoError("E2EE only supports X-Signing-Algo: ecdsa or ed25519")

    if not _is_hex(x_client_pub_key):
        raise E2EEInvalidPublicKeyError("X-Client-Pub-Key must be hex-encoded")
    if not _is_hex(x_model_pub_key):
        raise E2EEInvalidPublicKeyError("X-Model-Pub-Key must be hex-encoded")

    if algo == ECDSA:
        if _to_uncompressed_pubkey_bytes(x_model_pub_key) != _to_uncompressed_pubkey_bytes(
            local_model_public_key_hex(algo)
        ):
            raise E2EEModelKeyMismatchError("X-Model-Pub-Key does not match this proxy instance")
    else:
        if bytes.fromhex(x_model_pub_key) != bytes.fromhex(local_model_public_key_hex(algo)):
            raise E2EEModelKeyMismatchError("X-Model-Pub-Key does not match this proxy instance")

    version_header = (x_e2ee_version or "").strip()
    if version_header and version_header not in (E2EE_VERSION_V1, E2EE_VERSION_V2):
        raise E2EEInvalidVersionError("Unsupported X-E2EE-Version; supported versions are 1 and 2")

    has_nonce = bool(x_e2ee_nonce)
    has_timestamp = bool(x_e2ee_timestamp)
    if has_nonce ^ has_timestamp:
        raise E2EEHeaderMissingError(
            "X-E2EE-Nonce and X-E2EE-Timestamp must be provided together"
        )

    # Compatibility mode selection:
    # - explicit v2 header -> strict v2
    # - nonce+timestamp present -> strict v2 (implicit)
    # - otherwise -> legacy mode (near-compatible semantics)
    use_v2 = (version_header == E2EE_VERSION_V2) or (has_nonce and has_timestamp)
    version = E2EE_VERSION_V2 if use_v2 else E2EE_VERSION_V1

    parsed_ts: int | None = None
    if version == E2EE_VERSION_V2:
        if not x_e2ee_nonce or not x_e2ee_timestamp:
            raise E2EEHeaderMissingError("E2EE v2 requires X-E2EE-Nonce and X-E2EE-Timestamp headers")
        if len(x_e2ee_nonce) < 16:
            raise E2EEInvalidNonceError("X-E2EE-Nonce must be at least 16 characters")
        try:
            parsed_ts = int(x_e2ee_timestamp)
        except ValueError as exc:
            raise E2EEInvalidTimestampError("X-E2EE-Timestamp must be a unix timestamp in seconds") from exc

    return E2EEContext(
        signing_algo=algo,
        client_public_key_hex=x_client_pub_key,
        model_public_key_hex=x_model_pub_key,
        version=version,
        nonce=x_e2ee_nonce,
        timestamp=parsed_ts,
    )


def claim_e2ee_nonce(e2ee_ctx: E2EEContext) -> None:
    if e2ee_ctx.version == E2EE_VERSION_V2:
        if e2ee_ctx.nonce is None or e2ee_ctx.timestamp is None:
            raise E2EEHeaderMissingError("E2EE v2 requires nonce and timestamp for replay protection")
        _validate_replay_and_timestamp(e2ee_ctx.nonce, e2ee_ctx.timestamp, e2ee_ctx.signing_algo)


def get_e2ee_response_headers(e2ee_ctx: E2EEContext | None) -> dict[str, str]:
    if not e2ee_ctx:
        return {"X-E2EE-Applied": "false"}
    return {
        "X-E2EE-Applied": "true",
        "X-E2EE-Version": e2ee_ctx.version,
        "X-E2EE-Algo": e2ee_ctx.signing_algo,
    }


def _derive_aes_key(shared_secret: bytes, signing_algo: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_ECDSA_HKDF_INFO if signing_algo == ECDSA else _ED25519_HKDF_INFO,
    )
    return hkdf.derive(shared_secret)


def _aad_bytes(aad: str | None) -> bytes | None:
    if not aad:
        return None
    return aad.encode("utf-8")


def _build_request_aad(
    payload: dict[str, Any],
    message_index: int,
    content_index: int | None,
    e2ee_ctx: E2EEContext,
) -> str | None:
    if e2ee_ctx.version != E2EE_VERSION_V2:
        return None
    model = str(payload.get("model", ""))
    ci = "-" if content_index is None else str(content_index)
    return (
        f"v2|req|algo={e2ee_ctx.signing_algo}|model={model}|m={message_index}|c={ci}"
        f"|n={e2ee_ctx.nonce}|ts={e2ee_ctx.timestamp}"
    )


def _build_response_aad(
    response_obj: dict[str, Any],
    choice_index: int,
    field_name: str,
    e2ee_ctx: E2EEContext,
) -> str | None:
    if e2ee_ctx.version != E2EE_VERSION_V2:
        return None
    model = str(response_obj.get("model", ""))
    obj_id = str(response_obj.get("id", ""))
    return (
        f"v2|resp|algo={e2ee_ctx.signing_algo}|model={model}|id={obj_id}|choice={choice_index}|field={field_name}"
        f"|n={e2ee_ctx.nonce}|ts={e2ee_ctx.timestamp}"
    )


def _ed25519_public_to_x25519_public_key(pub_hex: str) -> x25519.X25519PublicKey:
    # Ed25519 public key is 32 bytes (little-endian y-coordinate with x-sign bit)
    y_bytes = bytes.fromhex(pub_hex)
    if len(y_bytes) != 32:
        raise E2EEInvalidPublicKeyError("Ed25519 public key must be 32 bytes")
    
    # RFC 7748: u = (1 + y) / (1 - y) mod p
    # y is the first 255 bits of the Ed25519 public key.
    y_int = int.from_bytes(y_bytes, byteorder="little")
    y = y_int & ((1 << 255) - 1)
    
    p = 2**255 - 19
    
    # RFC 7748: u = (1 + y) / (1 - y) mod p
    if y == 1:
        u = 0
    else:
        u = ((1 + y) * pow(1 - y, p - 2, p)) % p
    
    return x25519.X25519PublicKey.from_public_bytes(u.to_bytes(32, byteorder="little"))


def _ed25519_private_to_x25519_private_key():
    ed_private = _local_model_private_key(ED25519)
    seed = ed_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    h = hashlib.sha512(seed).digest()
    scalar = bytearray(h[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return x25519.X25519PrivateKey.from_private_bytes(bytes(scalar))


def decrypt_hex_for_model(
    encrypted_hex: str,
    signing_algo: str,
    aad: str | None = None,
) -> str:
    encrypted_data = bytes.fromhex(encrypted_hex)

    if signing_algo == ECDSA:
        if len(encrypted_data) < 65 + 12 + 16:
            raise E2EEDecryptionFailedError("Encrypted payload is too short")
        ephemeral_public_bytes = encrypted_data[:65]
        nonce = encrypted_data[65:77]
        ciphertext = encrypted_data[77:]

        ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), ephemeral_public_bytes
        )
        private_key = _local_model_private_key(ECDSA)
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)

    elif signing_algo == ED25519:
        if len(encrypted_data) < 32 + 12 + 16:
            raise E2EEDecryptionFailedError("Encrypted payload is too short")
        ephemeral_public_bytes = encrypted_data[:32]
        nonce = encrypted_data[32:44]
        ciphertext = encrypted_data[44:]

        ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
        private_key = _ed25519_private_to_x25519_private_key()
        shared_secret = private_key.exchange(ephemeral_public)
    else:
        raise ValueError("Unsupported signing algorithm")

    aes_key = _derive_aes_key(shared_secret, signing_algo)
    try:
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, _aad_bytes(aad))
    except Exception as exc:
        raise E2EEDecryptionFailedError(f"AES-GCM decryption failed: {exc}") from exc
    return plaintext.decode("utf-8")


def encrypt_for_client(
    plaintext: str,
    e2ee_ctx: E2EEContext,
    aad: str | None = None,
) -> str:
    if e2ee_ctx._aes_key is None or e2ee_ctx._ephemeral_public_bytes is None:
        if e2ee_ctx.signing_algo == ECDSA:
            client_public = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), _to_uncompressed_pubkey_bytes(e2ee_ctx.client_public_key_hex)
            )
            ephemeral_private = ec.generate_private_key(ec.SECP256K1())
            e2ee_ctx._ephemeral_public_bytes = ephemeral_private.public_key().public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )
            shared_secret = ephemeral_private.exchange(ec.ECDH(), client_public)
        elif e2ee_ctx.signing_algo == ED25519:
            client_public = _ed25519_public_to_x25519_public_key(e2ee_ctx.client_public_key_hex)
            ephemeral_private = x25519.X25519PrivateKey.generate()
            e2ee_ctx._ephemeral_public_bytes = ephemeral_private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            shared_secret = ephemeral_private.exchange(client_public)
        else:
            raise ValueError("Unsupported signing algorithm")

        e2ee_ctx._aes_key = _derive_aes_key(shared_secret, e2ee_ctx.signing_algo)

    nonce = os.urandom(12)
    ciphertext = AESGCM(e2ee_ctx._aes_key).encrypt(nonce, plaintext.encode("utf-8"), _aad_bytes(aad))
    return (e2ee_ctx._ephemeral_public_bytes + nonce + ciphertext).hex()


def _decrypt_content_value(
    content: Any,
    payload: dict[str, Any],
    message_index: int,
    e2ee_ctx: E2EEContext,
) -> Any:
    if content is None:
        return content

    if isinstance(content, str):
        if not _is_hex(content):
            raise ValueError("Encrypted message content must be hex-encoded")
        aad = _build_request_aad(payload, message_index, None, e2ee_ctx)
        return decrypt_hex_for_model(content, e2ee_ctx.signing_algo, aad)

    if isinstance(content, list):
        new_content: list[Any] = []
        for content_index, item in enumerate(content):
            if not isinstance(item, dict):
                new_content.append(item)
                continue

            item_copy = dict(item)
            if item_copy.get("type") == "text" and isinstance(item_copy.get("text"), str):
                text_value = item_copy["text"]
                if not _is_hex(text_value):
                    raise ValueError("Encrypted message text content must be hex-encoded")
                aad = _build_request_aad(payload, message_index, content_index, e2ee_ctx)
                item_copy["text"] = decrypt_hex_for_model(text_value, e2ee_ctx.signing_algo, aad)
            new_content.append(item_copy)
        return new_content

    return content


def _decrypt_message_payload(payload: dict[str, Any], e2ee_ctx: E2EEContext) -> dict[str, Any]:
    if "messages" not in payload or not isinstance(payload["messages"], list):
        return payload

    payload_copy = dict(payload)
    messages_copy: list[Any] = []

    for message_index, message in enumerate(payload["messages"]):
        if not isinstance(message, dict):
            messages_copy.append(message)
            continue

        message_copy = dict(message)
        if "content" in message_copy:
            message_copy["content"] = _decrypt_content_value(
                message_copy.get("content"), payload_copy, message_index, e2ee_ctx
            )
        messages_copy.append(message_copy)

    payload_copy["messages"] = messages_copy
    return payload_copy


def decrypt_request_json(payload: dict[str, Any], e2ee_ctx: E2EEContext | None) -> dict[str, Any]:
    if not e2ee_ctx:
        return payload
    return _decrypt_message_payload(payload, e2ee_ctx)


def _encrypt_field(
    container: dict[str, Any],
    field_name: str,
    e2ee_ctx: E2EEContext,
    aad: str | None,
) -> None:
    value = container.get(field_name)
    if isinstance(value, str):
        container[field_name] = encrypt_for_client(
            value,
            e2ee_ctx,
            aad,
        )


def encrypt_chat_completion_response(
    response_data: dict[str, Any], e2ee_ctx: E2EEContext | None
) -> dict[str, Any]:
    if not e2ee_ctx:
        return response_data

    for choice_index, choice in enumerate(response_data.get("choices", [])):
        message = choice.get("message") or {}
        _encrypt_field(
            message,
            "content",
            e2ee_ctx,
            _build_response_aad(response_data, choice_index, "content", e2ee_ctx),
        )
        _encrypt_field(
            message,
            "reasoning_content",
            e2ee_ctx,
            _build_response_aad(response_data, choice_index, "reasoning_content", e2ee_ctx),
        )

    return response_data


def encrypt_chat_completion_chunk(
    chunk_data: dict[str, Any], e2ee_ctx: E2EEContext | None
) -> dict[str, Any]:
    if not e2ee_ctx:
        return chunk_data

    for choice_index, choice in enumerate(chunk_data.get("choices", [])):
        delta = choice.get("delta") or {}
        _encrypt_field(
            delta,
            "content",
            e2ee_ctx,
            _build_response_aad(chunk_data, choice_index, "content", e2ee_ctx),
        )
        _encrypt_field(
            delta,
            "reasoning_content",
            e2ee_ctx,
            _build_response_aad(chunk_data, choice_index, "reasoning_content", e2ee_ctx),
        )

    return chunk_data
