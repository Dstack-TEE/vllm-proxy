import os
import json
import hashlib
import secrets
import requests
from requests.exceptions import ReadTimeout

BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")
API_KEY = os.environ.get("API_KEY", "")
MODEL_NAME = os.environ.get("MODEL_NAME", "")
SIGNING_ALGO = os.environ.get("SIGNING_ALGO", "ecdsa").lower()
CONNECT_TIMEOUT = int(os.environ.get("CONNECT_TIMEOUT", "15"))
READ_TIMEOUT = int(os.environ.get("READ_TIMEOUT", "300"))
MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "3"))


def _canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


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
                params={"model": MODEL_NAME, "nonce": nonce, "signing_algo": SIGNING_ALGO},
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
    assert "proxy" in data and "upstream" in data and "binding_proof" in data, "missing chain sections"

    # Proxy section
    proxy = data["proxy"]
    proxy_att = proxy["attestation"]
    assert proxy.get("signing_public_key"), "missing proxy.signing_public_key"
    assert proxy_att.get("signing_public_key") == proxy["signing_public_key"], "proxy signing_public_key mismatch"

    # Upstream hash consistency
    upstream = data["upstream"]
    upstream_att = upstream["attestation"]
    upstream_hash = hashlib.sha256(_canonical_json(upstream_att).encode("utf-8")).hexdigest()
    assert upstream.get("attestation_sha256") == upstream_hash, "upstream attestation hash mismatch"

    # Binding payload consistency
    bp = data["binding_proof"]
    payload = bp["payload"]
    assert payload.get("nonce") == nonce, "binding payload nonce mismatch"
    assert payload.get("model") == MODEL_NAME, "binding payload model mismatch"
    assert payload.get("upstream_attestation_sha256") == upstream_hash, "binding payload hash mismatch"
    assert bp.get("signing_algo") == SIGNING_ALGO, "binding signing_algo mismatch"
    assert bp.get("signature"), "binding signature missing"

    # Optional sanity: if upstream carries nonce, it should match
    upstream_nonce = upstream_att.get("request_nonce") or upstream_att.get("nonce")
    if upstream_nonce is not None:
        assert upstream_nonce == nonce, "upstream nonce does not match request nonce"

    print("[OK] /v1/attestation/chain validated")
    print("nonce:", nonce)
    print("model:", MODEL_NAME)
    print("signing_algo:", SIGNING_ALGO)
    print("upstream_attestation_sha256:", upstream_hash)


if __name__ == "__main__":
    main()
