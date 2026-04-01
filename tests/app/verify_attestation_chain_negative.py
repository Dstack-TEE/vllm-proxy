import os
import requests

BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")
API_KEY = os.environ.get("API_KEY", "")
MODEL_NAME = os.environ.get("MODEL_NAME", "")
SIGNING_ALGO = os.environ.get("SIGNING_ALGO", "ecdsa").lower()


def main():
    if not BASE_URL or not API_KEY or not MODEL_NAME:
        raise RuntimeError("Please set BASE_URL, API_KEY, MODEL_NAME")

    # nonce deliberately too short, should fail with invalid_nonce
    resp = requests.get(
        f"{BASE_URL}/v1/attestation/chain",
        params={"model": MODEL_NAME, "nonce": "short", "signing_algo": SIGNING_ALGO},
        headers={"Authorization": f"Bearer {API_KEY}"},
        timeout=60,
    )

    print("status:", resp.status_code)
    print("body:", resp.text)

    if resp.status_code != 400:
        raise RuntimeError(f"Expected 400 for short nonce, got {resp.status_code}")

    data = resp.json()
    err_type = (data.get("error") or {}).get("type")
    if err_type != "invalid_nonce":
        raise RuntimeError(f"Expected error.type=invalid_nonce, got {err_type}")

    print("[OK] negative check passed (invalid_nonce)")


if __name__ == "__main__":
    main()
