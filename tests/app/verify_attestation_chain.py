import os
import json
import hashlib
import secrets
import requests
from requests.exceptions import ReadTimeout
from eth_account import Account
from eth_account.messages import encode_defunct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")
API_KEY = os.environ.get("API_KEY", "")
MODEL_NAME = os.environ.get("MODEL_NAME", "")
SIGNING_ALGO = os.environ.get("SIGNING_ALGO", "ecdsa").lower()
CONNECT_TIMEOUT = int(os.environ.get("CONNECT_TIMEOUT", "15"))
READ_TIMEOUT = int(os.environ.get("READ_TIMEOUT", "300"))
MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "3"))
VERIFY_MODE = os.environ.get("VERIFY_MODE", "proxy").lower()


def _canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _verify_binding_signature(binding_proof: dict):
    payload_text = _canonical_json(binding_proof["payload"])
    signing_algo = binding_proof.get("signing_algo")
    signature = binding_proof.get("signature")
    signing_address = binding_proof.get("signing_address")

    if signing_algo == "ecdsa":
        if not signature or not signature.startswith("0x"):
            raise RuntimeError("invalid ecdsa signature format")
        recovered = Account.recover_message(
            encode_defunct(text=payload_text),
            signature=signature,
        )
        if recovered.lower() != (signing_address or "").lower():
            raise RuntimeError(
                f"binding signature mismatch: recovered={recovered}, expected={signing_address}"
            )
        return recovered

    if signing_algo == "ed25519":
        # In this project ed25519 signing_address is the raw public key hex.
        pubkey_hex = signing_address or ""
        if len(pubkey_hex) != 64:
            raise RuntimeError("invalid ed25519 signing_address/public key")
        pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pubkey.verify(bytes.fromhex(signature), payload_text.encode("utf-8"))
        return pubkey_hex

    raise RuntimeError(f"unsupported signing_algo: {signing_algo}")


def main():
    if not BASE_URL or not API_KEY or not MODEL_NAME:
        raise RuntimeError("Please set BASE_URL, API_KEY, MODEL_NAME")

    # Use 32-byte hex nonce to match attestation implementations that expect hex challenge.
    nonce = secrets.token_hex(32)

    url = f"{BASE_URL}/v1/attestation/chain"

    resp = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(
                url,
                params={"model": MODEL_NAME, "nonce": nonce, "signing_algo": SIGNING_ALGO, "verify_mode": VERIFY_MODE},
                headers={"Authorization": f"Bearer {API_KEY}"},
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )
        except ReadTimeout:
            if attempt == MAX_RETRIES:
                raise RuntimeError(
                    f"Read timeout after {MAX_RETRIES} attempts (connect={CONNECT_TIMEOUT}s, read={READ_TIMEOUT}s)."
                )
            print(f"attempt {attempt}/{MAX_RETRIES} timed out, retrying...")
            continue

        print("status:", resp.status_code)
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After")
            print("body:", resp.text)
            if attempt == MAX_RETRIES:
                raise RuntimeError(
                    "429 from /v1/attestation/chain (likely upstream Chutes attestation rate limit). "
                    f"Retry-After={retry_after}."
                )
            print(f"attempt {attempt}/{MAX_RETRIES} got 429, retrying...")
            continue

        if resp.status_code >= 400:
            print("body:", resp.text)
        resp.raise_for_status()
        break

    if resp is None:
        raise RuntimeError("No response received")

    data = resp.json()

    # Top-level structure checks
    assert data.get("version") == "1", "unexpected chain version"
    assert data.get("verify_mode") == VERIFY_MODE, f"unexpected verify_mode: {data.get('verify_mode')}"
    assert "proxy" in data, "missing proxy section"

    proxy = data["proxy"]
    proxy_att = proxy["attestation"]
    assert proxy.get("signing_public_key"), "missing proxy.signing_public_key"
    assert proxy_att.get("signing_public_key") == proxy["signing_public_key"], "proxy signing_public_key mismatch"

    if VERIFY_MODE == "passthrough":
        assert "upstream" in data and "binding_proof" in data, "missing passthrough sections"
        upstream = data["upstream"]
        upstream_att = upstream["attestation"]
        upstream_hash = hashlib.sha256(_canonical_json(upstream_att).encode("utf-8")).hexdigest()
        assert upstream.get("attestation_sha256") == upstream_hash, "upstream attestation hash mismatch"

        bp = data["binding_proof"]
        payload = bp["payload"]
        assert payload.get("nonce") == nonce, "binding payload nonce mismatch"
        assert payload.get("model") == MODEL_NAME, "binding payload model mismatch"
        assert payload.get("upstream_attestation_sha256") == upstream_hash, "binding payload hash mismatch"
        assert bp.get("signing_algo") == SIGNING_ALGO, "binding signing_algo mismatch"
        assert bp.get("signature"), "binding signature missing"

        recovered_signer = _verify_binding_signature(bp)
        proxy_signing_address = proxy_att.get("signing_address")
        if proxy_signing_address:
            assert recovered_signer.lower() == proxy_signing_address.lower(), (
                f"proxy signing address mismatch: recovered={recovered_signer}, proxy={proxy_signing_address}"
            )

        print("[OK] /v1/attestation/chain passthrough validated")
        print("binding_signer:", recovered_signer)
        print("upstream_attestation_sha256:", upstream_hash)
    else:
        assert "verification_receipt" in data, "missing verification_receipt"
        receipt = data["verification_receipt"]
        assert receipt.get("signature"), "receipt signature missing"
        payload = receipt.get("payload") or {}
        assert payload.get("result") == "pass", "receipt result is not pass"
        assert payload.get("model") == MODEL_NAME, "receipt model mismatch"
        assert payload.get("nonce") == nonce, "receipt nonce mismatch"

        print("[OK] /v1/attestation/chain proxy mode validated")

    print("nonce:", nonce)
    print("model:", MODEL_NAME)
    print("signing_algo:", SIGNING_ALGO)
    print("verify_mode:", VERIFY_MODE)


if __name__ == "__main__":
    main()
