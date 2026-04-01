import os
import requests

BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")
API_KEY = os.environ.get("API_KEY", "")
MODEL_NAME = os.environ.get("MODEL_NAME", "")  # kept for consistent runner env
SIGNING_ALGO = os.environ.get("SIGNING_ALGO", "ecdsa").lower()


def main():
    if not BASE_URL or not API_KEY:
        raise RuntimeError("Please set BASE_URL and API_KEY")

    url = f"{BASE_URL}/v1/attestation/report"
    resp = requests.get(
        url,
        params={"signing_algo": SIGNING_ALGO},
        headers={"Authorization": f"Bearer {API_KEY}"},
        timeout=60,
    )

    print("status:", resp.status_code)
    resp.raise_for_status()
    data = resp.json()

    assert "signing_public_key" in data, "missing signing_public_key"
    assert "all_attestations" in data and isinstance(data["all_attestations"], list), "missing all_attestations"
    assert data["all_attestations"], "all_attestations is empty"
    assert (
        data["all_attestations"][0].get("signing_public_key") == data["signing_public_key"]
    ), "top-level signing_public_key mismatch"

    expected_len = 128 if SIGNING_ALGO == "ecdsa" else 64
    assert len(data["signing_public_key"]) == expected_len, (
        f"unexpected signing_public_key length: {len(data['signing_public_key'])}, "
        f"expected {expected_len} for {SIGNING_ALGO}"
    )

    print("[OK] /v1/attestation/report validated")
    print("signing_algo:", SIGNING_ALGO)
    print("signing_public_key len:", len(data["signing_public_key"]))
    if MODEL_NAME:
        print("model_name (unused in this check):", MODEL_NAME)


if __name__ == "__main__":
    main()
