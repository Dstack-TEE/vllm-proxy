import os, json, time, hashlib, requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BASE_URL = os.environ["BASE_URL"].rstrip("/")
API_KEY = os.environ["API_KEY"]
MODEL_NAME = os.environ.get("MODEL_NAME")

def ed_pub_to_x25519(pub_hex: str) -> x25519.X25519PublicKey:
    raw = bytes.fromhex(pub_hex)
    if len(raw) != 32:
        raise ValueError("ed25519 pubkey must be 32 bytes")
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

def main():
    # 1) get server ed25519 pubkey
    att = requests.get(
        f"{BASE_URL}/v1/attestation/report?signing_algo=ed25519",
        headers={"Authorization": f"Bearer {API_KEY}"},
        timeout=60,
    )
    att.raise_for_status()
    model_pub_hex = att.json()["signing_public_key"]
    print("server ed25519 pubkey len:", len(model_pub_hex))

    # 2) client temporary key
    client_ed = ed25519.Ed25519PrivateKey.generate()
    client_pub_hex = client_ed.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    client_x = ed_priv_to_x25519(client_ed)

    # 3) encrypt request
    nonce_hdr = "n" + str(int(time.time())) + "abcd1234abcd"
    ts_hdr = str(int(time.time()))
    prompt = "please only reply: E2EE_ED25519_OK"

    server_xpub = ed_pub_to_x25519(model_pub_hex)
    eph = x25519.X25519PrivateKey.generate()
    shared = eph.exchange(server_xpub)
    key = derive(shared)
    aad_req = f"v2|req|algo=ed25519|model={MODEL_NAME}|m=0|c=-|n={nonce_hdr}|ts={ts_hdr}".encode()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, prompt.encode("utf-8"), aad_req)
    eph_pub = eph.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    enc_prompt_hex = (eph_pub + nonce + ct).hex()

    payload = {
        "model": MODEL_NAME,
        "stream": False,
        "messages": [{"role": "user", "content": enc_prompt_hex}],
    }
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "X-Signing-Algo": "ed25519",
        "X-Client-Pub-Key": client_pub_hex,
        "X-Model-Pub-Key": model_pub_hex,
        "X-E2EE-Version": "2",
        "X-E2EE-Nonce": nonce_hdr,
        "X-E2EE-Timestamp": ts_hdr,
    }

    # 4) first request
    r = requests.post(f"{BASE_URL}/v1/chat/completions", headers=headers, data=json.dumps(payload), timeout=120)
    print("first status:", r.status_code)
    print("e2ee headers:", {k: v for k, v in r.headers.items() if k.lower().startswith("x-e2ee")})
    print("body prefix:", r.text[:180])
    r.raise_for_status()
    data = r.json()

    # 5) decrypt response
    enc_resp = data["choices"][0]["message"]["content"]
    blob = bytes.fromhex(enc_resp)
    eph2 = x25519.X25519PublicKey.from_public_bytes(blob[:32])
    nonce2 = blob[32:44]
    ct2 = blob[44:]
    shared2 = client_x.exchange(eph2)
    key2 = derive(shared2)
    aad_resp = f"v2|resp|algo=ed25519|model={data.get('model','')}|id={data.get('id','')}|choice=0|field=content|n={nonce_hdr}|ts={ts_hdr}".encode()
    plain = AESGCM(key2).decrypt(nonce2, ct2, aad_resp).decode("utf-8")
    print("decrypted response:", plain)

    clean_text = plain.replace("_", "").replace(" ", "").replace("\n", "").upper()
    if "E2EEED25519OK" not in clean_text:
        raise AssertionError(f"decrypted text '{plain}' does not contain expected marker")
    print("[OK] non-stream decrypt assertion passed")

    # 6) replay test
    r2 = requests.post(f"{BASE_URL}/v1/chat/completions", headers=headers, data=json.dumps(payload), timeout=120)
    print("replay status(expect 400):", r2.status_code)
    print("replay body:", r2.text[:160])

if __name__ == "__main__":
    main()