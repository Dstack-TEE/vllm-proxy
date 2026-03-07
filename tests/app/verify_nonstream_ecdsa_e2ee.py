import os
import json
import time
import requests
from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BASE_URL = os.environ.get("BASE_URL").rstrip("/")
API_KEY = os.environ["API_KEY"]
MODEL_NAME = os.environ.get("MODEL_NAME").rstrip("/")
HKDF_INFO = b"ecdsa_encryption"

def to_uncompressed(pub_hex: str) -> bytes:
    b = bytes.fromhex(pub_hex)
    if len(b) == 64:
        return b"\x04" + b
    if len(b) == 65 and b[0] == 0x04:
        return b
    raise ValueError(f"bad pubkey length: {len(b)}")

def derive_key(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=HKDF_INFO).derive(shared)

def encrypt_for_model(plaintext: str, model_pub_hex: str, aad: Optional[str]):
    model_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), to_uncompressed(model_pub_hex))
    eph_priv = ec.generate_private_key(ec.SECP256K1())
    eph_pub = eph_priv.public_key()
    shared = eph_priv.exchange(ec.ECDH(), model_pub)
    key = derive_key(shared)
    nonce = os.urandom(12)
    aad_bytes = aad.encode("utf-8") if aad else None
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad_bytes)
    eph_pub_bytes = eph_pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return (eph_pub_bytes + nonce + ct).hex()

def decrypt_from_model(enc_hex: str, client_priv, aad: Optional[str]):
    blob = bytes.fromhex(enc_hex)
    eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), blob[:65])
    nonce = blob[65:77]
    ct = blob[77:]
    shared = client_priv.exchange(ec.ECDH(), eph_pub)
    key = derive_key(shared)
    aad_bytes = aad.encode("utf-8") if aad else None
    pt = AESGCM(key).decrypt(nonce, ct, aad_bytes)
    return pt.decode("utf-8")

def client_pub_hex64(client_priv):
    pub = client_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return pub[1:].hex()

def test_v1(model_pub_hex, client_priv, client_pub):
    print("--- Testing E2EE v1 (Legacy) ---")
    prompt = "please only reply: E2EE_V1_OK"
    enc_prompt = encrypt_for_model(prompt, model_pub_hex, None)
    
    payload = {
        "model": MODEL_NAME,
        "stream": False,
        "messages": [{"role": "user", "content": enc_prompt}],
    }
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "X-Signing-Algo": "ecdsa",
        "X-Client-Pub-Key": client_pub,
        "X-Model-Pub-Key": model_pub_hex,
    }
    
    r = requests.post(f"{BASE_URL}/v1/chat/completions", headers=headers, json=payload, timeout=120)
    print("v1 status:", r.status_code)
    r.raise_for_status()
    data = r.json()
    
    enc_answer = data["choices"][0]["message"]["content"]
    plain = decrypt_from_model(enc_answer, client_priv, None)
    print("v1 decrypted:", plain)
    
    clean_text = plain.replace("_", "").replace(" ", "").replace("\n", "").upper()
    if "V1OK" not in clean_text:
        raise AssertionError(f"v1 failed: {plain}")
    print("[OK] v1 pass")

def test_v2(model_pub_hex, client_priv, client_pub):
    print("--- Testing E2EE v2 (Strict) ---")
    nonce = "n" + str(int(time.time())) + "abcd1234abcd"
    ts = str(int(time.time()))
    prompt = "please only reply: E2EE_V2_OK"
    
    req_aad = f"v2|req|algo=ecdsa|model={MODEL_NAME}|m=0|c=-|n={nonce}|ts={ts}"
    enc_prompt = encrypt_for_model(prompt, model_pub_hex, req_aad)
    
    payload = {
        "model": MODEL_NAME,
        "stream": False,
        "messages": [{"role": "user", "content": enc_prompt}],
    }
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "X-Signing-Algo": "ecdsa",
        "X-Client-Pub-Key": client_pub,
        "X-Model-Pub-Key": model_pub_hex,
        "X-E2EE-Nonce": nonce,
        "X-E2EE-Timestamp": ts,
    }
    
    r = requests.post(f"{BASE_URL}/v1/chat/completions", headers=headers, json=payload, timeout=120)
    print("v2 status:", r.status_code)
    r.raise_for_status()
    data = r.json()
    
    enc_answer = data["choices"][0]["message"]["content"]
    resp_aad = f"v2|resp|algo=ecdsa|model={data.get('model','')}|id={data.get('id','')}|choice=0|field=content|n={nonce}|ts={ts}"
    plain = decrypt_from_model(enc_answer, client_priv, resp_aad)
    print("v2 decrypted:", plain)
    
    clean_text = plain.replace("_", "").replace(" ", "").replace("\n", "").upper()
    if "V2OK" not in clean_text:
        raise AssertionError(f"v2 failed: {plain}")
    print("[OK] v2 pass")

def main():
    # 1) get server ecdsa pubkey from attestation
    att = requests.get(
        f"{BASE_URL}/v1/attestation/report?signing_algo=ecdsa",
        headers={"Authorization": f"Bearer {API_KEY}"},
        timeout=60
    )
    att.raise_for_status()
    model_pub_hex = att.json().get("signing_public_key")
    if not model_pub_hex:
        raise RuntimeError("signing_public_key not found in attestation report")
    print(f"[OK] server ecdsa pubkey (len={len(model_pub_hex)})")

    # 2) client temporary key
    client_priv = ec.generate_private_key(ec.SECP256K1())
    client_pub = client_pub_hex64(client_priv)

    # 3) run tests
    test_v1(model_pub_hex, client_priv, client_pub)
    print()
    test_v2(model_pub_hex, client_priv, client_pub)

if __name__ == "__main__":
    main()
