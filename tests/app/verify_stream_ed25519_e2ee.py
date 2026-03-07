import os
import json
import time
import hashlib
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BASE_URL = os.environ.get("BASE_URL").rstrip("/")
API_KEY = os.environ["API_KEY"]
MODEL_NAME = os.environ.get("MODEL_NAME").rstrip("/")

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

def ed_pub_to_x25519(pub_hex: str) -> x25519.X25519PublicKey:
    raw = bytes.fromhex(pub_hex)
    if len(raw) != 32:
        raise ValueError(f"ed25519 pubkey must be 32 bytes, got {len(raw)}")
    y = bytearray(raw)
    y[31] &= 0x7F
    yi = int.from_bytes(y, "little")
    p = 2**255 - 19
    if yi == 1:
        u = 0
    else:
        one_minus = (1 - yi) % p
        inv = pow(one_minus, p - 2, p)
        u = ((1 + yi) * inv) % p
    return x25519.X25519PublicKey.from_public_bytes(u.to_bytes(32, "little"))

def ed_priv_to_x25519(priv: ed25519.Ed25519PrivateKey) -> x25519.X25519PrivateKey:
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    h = hashlib.sha512(seed).digest()
    s = bytearray(h[:32])
    s[0] &= 248
    s[31] &= 127
    s[31] |= 64
    return x25519.X25519PrivateKey.from_private_bytes(bytes(s))

def derive(shared: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ed25519_encryption",
    ).derive(shared)

def encrypt_prompt_ed25519(prompt: str, model_pub_hex: str, aad_req: bytes | None) -> str:
    server_xpub = ed_pub_to_x25519(model_pub_hex)
    eph = x25519.X25519PrivateKey.generate()
    shared = eph.exchange(server_xpub)
    key = derive(shared)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, prompt.encode("utf-8"), aad_req)
    eph_pub = eph.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (eph_pub + nonce + ct).hex()

def decrypt_chunk(enc_hex: str, client_x: x25519.X25519PrivateKey, aad_resp: bytes | None) -> str:
    blob = bytes.fromhex(enc_hex)
    if len(blob) < 32 + 12 + 16:
        raise ValueError("chunk too short")
    eph = x25519.X25519PublicKey.from_public_bytes(blob[:32])
    nonce = blob[32:44]
    ct = blob[44:]
    shared = client_x.exchange(eph)
    key = derive(shared)
    return AESGCM(key).decrypt(nonce, ct, aad_resp).decode("utf-8")

def test_v1_stream(sess, verify, model_pub_hex, client_x, client_pub_hex):
    print("--- Testing E2EE v1 Stream (Legacy) ---")
    marker = "STREAM_V1_OK"
    prompt = f"please only reply: {marker}"
    
    enc_prompt_hex = encrypt_prompt_ed25519(prompt, model_pub_hex, None)
    
    payload = {
        "model": MODEL_NAME,
        "stream": True,
        "messages": [{"role": "user", "content": enc_prompt_hex}],
    }
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "X-Signing-Algo": "ed25519",
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
                parts.append(decrypt_chunk(enc_piece, client_x, None))
                
    text = "".join(parts)
    print("v1 decrypted:", text)
    clean_text = text.replace("_", "").replace(" ", "").replace("\n", "").upper()
    if "V1OK" not in clean_text:
        raise AssertionError(f"v1 failed: {text}")
    print("[OK] v1 pass")

def test_v2_stream(sess, verify, model_pub_hex, client_x, client_pub_hex):
    print("--- Testing E2EE v2 Stream (Strict) ---")
    nonce_hdr = "n" + str(int(time.time())) + "abcd1234abcd"
    ts_hdr = str(int(time.time()))
    marker = "STREAM_V2_OK"
    prompt = f"please only reply: {marker}"
    
    aad_req = f"v2|req|algo=ed25519|model={MODEL_NAME}|m=0|c=-|n={nonce_hdr}|ts={ts_hdr}".encode("utf-8")
    enc_prompt_hex = encrypt_prompt_ed25519(prompt, model_pub_hex, aad_req)
    
    payload = {
        "model": MODEL_NAME,
        "stream": True,
        "messages": [{"role": "user", "content": enc_prompt_hex}],
    }
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "X-Signing-Algo": "ed25519",
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
                aad_resp = f"v2|resp|algo=ed25519|model={obj.get('model','')}|id={obj.get('id','')}|choice={ch.get('index',0)}|field=content|n={nonce_hdr}|ts={ts_hdr}".encode("utf-8")
                parts.append(decrypt_chunk(enc_piece, client_x, aad_resp))
                
    text = "".join(parts)
    print("v2 decrypted:", text)
    clean_text = text.replace("_", "").replace(" ", "").replace("\n", "").upper()
    if "V2OK" not in clean_text:
        raise AssertionError(f"v2 failed: {text}")
    print("[OK] v2 pass")

def main():
    sess = build_session()
    verify = verify_arg()
    
    att_url = f"{BASE_URL}/v1/attestation/report?signing_algo=ed25519"
    att = sess.get(att_url, headers={"Authorization": f"Bearer {API_KEY}"}, verify=verify)
    att.raise_for_status()
    model_pub_hex = att.json()["signing_public_key"]
    
    client_ed = ed25519.Ed25519PrivateKey.generate()
    client_pub_hex = client_ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    client_x = ed_priv_to_x25519(client_ed)
    
    test_v1_stream(sess, verify, model_pub_hex, client_x, client_pub_hex)
    print()
    test_v2_stream(sess, verify, model_pub_hex, client_x, client_pub_hex)

if __name__ == "__main__":
    main()