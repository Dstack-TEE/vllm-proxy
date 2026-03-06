# Phala vLLM Proxy E2EE Protocol Specification

This document defines the End-to-End Encryption (E2EE) protocol used by the Phala vLLM Proxy to ensure data privacy between clients and the Model running in a Trusted Execution Environment (TEE).

## 1. Overview

The protocol supports two major versions:
- **v1**: Basic E2EE (Deprecated, not recommended for new implementations).
- **v2**: Enhanced E2EE with AAD (Additional Authenticated Data) and Replay Protection.

Supported Algorithms:
- **ECDSA**: Using `secp256k1` curve for signing and ECDH key exchange.
- **Ed25519**: Using Ed25519 for signing and X25519 for key exchange (via birational equivalence).

## 2. Handshake and Key Derivation

### 2.1 Server Public Key Discovery
Clients can obtain the server's public key (either ECDSA or Ed25519 depending on the environment) via the `/v1/attestation/report` endpoint.

The response contains:
- `signing_address`: The EVM address (for ECDSA) or 32-byte raw public key hex (64 chars) (for Ed25519).
- `signing_public_key`: The raw hex-encoded public key (no `0x` prefix). Available at both the top-level and within each item in `all_attestations`.
  - **Ed25519**: 32 bytes (64 hex characters). 
  - **ECDSA**: 64 bytes (128 hex characters), representing uncompressed point `(x, y)` without the `04` prefix.

### 2.2 Client Ephemeral Key Generation
For each encryption operation, the client generates an ephemeral key pair of the same type as the server's key.

### 2.3 Shared Secret and AES Key
1. Perform ECDH (or X25519 exchange) between the client's ephemeral private key and the server's public key.
2. Derivation via HKDF-SHA256:
   - **ECDSA Info**: `b"ecdsa_encryption"`
   - **Ed25519 Info**: `b"ed25519_encryption"`
   - **Length**: 32 bytes
   - **Salt**: `None`

## 3. Request Encryption (v2)

### 3.1 Headers
The following headers are required for E2EE v2:
- `X-Signing-Algo`: `ecdsa` or `ed25519`
- `X-Client-Pub-Key`: Client's public key (Hex)
- `X-Model-Pub-Key`: Server's public key (Hex)
- `X-E2EE-Version`: `2`
- `X-E2EE-Nonce`: Minimum 16-character unique string per request.
- `X-E2EE-Timestamp`: Unix timestamp (seconds).

### 3.2 AAD Construction (v2 Request)
Format: `v2|req|algo={algo}|model={model}|m={message_index}|c={content_index}|n={nonce}|ts={timestamp}`
- `algo`: lowercase signing algo name.
- `model`: Model name from request payload.
- `message_index`: 0-indexed position in `messages` array.
- `content_index`: `-` for top-level `content` string, or 0-indexed if content is a list of items.

### 3.3 Payload Format
Encapsulated fields (like `messages[i].content`) are replaced with:
`ephemeral_public_key (bytes) + nonce (12 bytes) + ciphertext (bytes)`
The result is Hex-encoded.

## 4. Response Encryption (v2)

### 4.1 Response Headers
The server returns:
- `X-E2EE-Applied`: `true`
- `X-E2EE-Version`: `2`
- `X-E2EE-Alg`: Same as requested.

### 4.2 AAD Construction (v2 Response)
Format: `v2|resp|algo={algo}|model={model}|id={obj_id}|choice={choice_index}|field={field_name}|n={nonce}|ts={timestamp}`
- `id`: Chat completion ID (`chatcmpl-...`).
- `choice_index`: 0-indexed position in `choices` array.
- `field_name`: `content` or `reasoning_content`.
- `nonce/timestamp`: Reused from the original request.

## 5. Error Codes

| Error Type | Meaning |
|---|---|
| `e2ee_header_missing` | Required E2EE headers are missing. |
| `e2ee_invalid_signing_algo` | Unsupported algorithm specified. |
| `e2ee_invalid_public_key` | Public key format or length is invalid. |
| `e2ee_model_key_mismatch` | `X-Model-Pub-Key` does not match the server instance. |
| `e2ee_invalid_version` | Unsupported `X-E2EE-Version`. |
| `e2ee_invalid_nonce` | Nonce length or format is invalid (e.g., < 16 chars). |
| `e2ee_replay_detected` | Nonce + Timestamp has already been consumed. |
| `e2ee_invalid_timestamp` | Timestamp is malformed or outside the allowed window. |
| `e2ee_decryption_failed` | MAC tag mismatch or invalid ciphertext format. |
