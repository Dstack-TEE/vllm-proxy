import os
import json
import time
import requests
from typing import Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BASE_URL = os.environ.get("BASE_URL").rstrip("/")
API_KEY = os.environ["API_KEY"]
MODEL_NAME = os.environ.get("MODEL_NAME").rstrip("/")
HKDF_INFO = b"ecdsa_encryption"

# TLS_INSECURE=1 skip cert verify (only for troubleshooting)
TLS_INSECURE = os.environ.get("TLS_INSECURE", "0") == "1"
CA_BUNDLE = os.environ.get("REQUESTS_CA_BUNDLE") # optional: custom CA

TIMEOUT = (10, 180) # (connect, read)

def build_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=0.8,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "POST"]),
        raise_on_status=False,
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.mount("http://", HTTPAdapter(max_retries=retries))
    return s

def verify_arg():
    if TLS_INSECURE:
        requests.packages.urllib3.disable_warnings() # type: ignore
        return False
    if CA_BUNDLE:
        return CA_BUNDLE
    return True

def to_uncompressed(pub_hex: str) -> bytes:
    b = bytes.fromhex(pub_hex)
    if len(b) == 64:
        return b"\x04" + b
    if len(b) == 65 and b[0] == 0x04:
        return b
    raise ValueError(f"bad pubkey length: {len(b)}")

def derive_key(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=HKDF_INFO).derive(shared)

def encrypt_for_model_ecdsa(plaintext: str, model_pub_hex: str, aad_req: Optional[bytes]) -> str:
    model_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), to_uncompressed(model_pub_hex))
    eph_priv = ec.generate_private_key(ec.SECP256K1())
    eph_pub = eph_priv.public_key()
    shared = eph_priv.exchange(ec.ECDH(), model_pub)
    key = derive_key(shared)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad_req)
    eph_pub_bytes = eph_pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return (eph_pub_bytes + nonce + ct).hex()

def decrypt_chunk_ecdsa(enc_hex: str, client_priv: ec.EllipticCurvePrivateKey, aad_resp: Optional[bytes]) -> str:
    blob = bytes.fromhex(enc_hex)
    if len(blob) < 65 + 12 + 16:
        raise ValueError("chunk too short")
    eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), blob[:65])
    nonce = blob[65:77]
    ct = blob[77:]
    shared = client_priv.exchange(ec.ECDH(), eph_pub)
    key = derive_key(shared)
    return AESGCM(key).decrypt(nonce, ct, aad_resp).decode("utf-8")

def client_pub_hex64(client_priv):
    pub = client_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return pub[1:].hex()

def test_v1_stream(sess, verify, model_pub_hex, client_priv, client_pub_hex):
    print("--- Testing E2EE v1 Stream (Legacy) ---")
    marker = "STREAM_V1_OK"
    prompt = f"please only reply: {marker}"
    
    enc_prompt_hex = encrypt_for_model_ecdsa(prompt, model_pub_hex, None)
    
    payload = {
        "model": MODEL_NAME,
        "stream": True,
        "messages": [{"role": "user", "content": enc_prompt_hex}],
    }
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "X-Signing-Algo": "ecdsa",
        "X-Client-Pub-Key": client_pub_hex,
        "X-Model-Pub-Key": model_pub_hex,
    }
    
    url = f"{BASE_URL}/v1/chat/completions"
    resp = sess.post(url, headers=headers, json=payload, stream=True, timeout=TIMEOUT, verify=verify)
    print("v1 status:", resp.status_code)
    resp.raise_for_status()
    
    parts = []
    seen_data_chunk = False
    for line in resp.iter_lines(decode_unicode=True):
        if not line or not line.startswith("data: "): continue
        data = line[6:].strip()
        if data == "[DONE]": break
        
        obj = json.loads(data)
        for ch in obj.get("choices", []):
            delta = ch.get("delta", {})
            enc_piece = delta.get("content")
            if isinstance(enc_piece, str) and enc_piece:
                seen_data_chunk = True
                parts.append(decrypt_chunk_ecdsa(enc_piece, client_priv, None))
                
    text = "".join(parts)
    print("v1 decrypted:", text)
    clean_text = text.replace("_", "").replace(" ", "").replace("\n", "").upper()
    if "V1OK" not in clean_text:
        raise AssertionError(f"v1 failed: {text}")
    print("[OK] v1 pass")

def test_v2_stream(sess, verify, model_pub_hex, client_priv, client_pub_hex):
    print("--- Testing E2EE v2 Stream (Strict) ---")
    nonce_hdr = "n" + str(int(time.time())) + "abcd1234abcd"
    ts_hdr = str(int(time.time()))
    marker = "STREAM_V2_OK"
    prompt = f"please only reply: {marker}"
    
    aad_req = f"v2|req|algo=ecdsa|model={MODEL_NAME}|m=0|c=-|n={nonce_hdr}|ts={ts_hdr}".encode("utf-8")
    enc_prompt_hex = encrypt_for_model_ecdsa(prompt, model_pub_hex, aad_req)
    
    payload = {
        "model": MODEL_NAME,
        "stream": True,
        "messages": [{"role": "user", "content": enc_prompt_hex}],
    }
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "X-Signing-Algo": "ecdsa",
        "X-Client-Pub-Key": client_pub_hex,
        "X-Model-Pub-Key": model_pub_hex,
        "X-E2EE-Nonce": nonce_hdr,
        "X-E2EE-Timestamp": ts_hdr,
    }
    
    url = f"{BASE_URL}/v1/chat/completions"
    resp = sess.post(url, headers=headers, json=payload, stream=True, timeout=TIMEOUT, verify=verify)
    print("v2 status:", resp.status_code)
    resp.raise_for_status()
    
    parts = []
    seen_data_chunk = False
    for line in resp.iter_lines(decode_unicode=True):
        if not line or not line.startswith("data: "): continue
        data = line[6:].strip()
        if data == "[DONE]": break
        
        obj = json.loads(data)
        for ch in obj.get("choices", []):
            delta = ch.get("delta", {})
            enc_piece = delta.get("content")
            if isinstance(enc_piece, str) and enc_piece:
                seen_data_chunk = True
                aad_resp = f"v2|resp|algo=ecdsa|model={obj.get('model','')}|id={obj.get('id','')}|choice={ch.get('index',0)}|field=content|n={nonce_hdr}|ts={ts_hdr}".encode("utf-8")
                parts.append(decrypt_chunk_ecdsa(enc_piece, client_priv, aad_resp))
                
    text = "".join(parts)
    print("v2 decrypted:", text)
    clean_text = text.replace("_", "").replace(" ", "").replace("\n", "").upper()
    if "V2OK" not in clean_text:
        raise AssertionError(f"v2 failed: {text}")
    print("[OK] v2 pass")

def main():
    sess = build_session()
    verify = verify_arg()
    
    att_url = f"{BASE_URL}/v1/attestation/report?signing_algo=ecdsa"
    att = sess.get(att_url, headers={"Authorization": f"Bearer {API_KEY}"}, verify=verify)
    att.raise_for_status()
    model_pub_hex = att.json()["signing_public_key"]
    
    client_priv = ec.generate_private_key(ec.SECP256K1())
    client_pub_hex = client_pub_hex64(client_priv)
    
    test_v1_stream(sess, verify, model_pub_hex, client_priv, client_pub_hex)
    print()
    test_v2_stream(sess, verify, model_pub_hex, client_priv, client_pub_hex)

if __name__ == "__main__":
    main()
