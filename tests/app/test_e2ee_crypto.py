import pytest
import os
import sys
from tests.app.test_helpers import setup_test_environment

setup_test_environment()
sys.modules["app.quote.quote"] = __import__("tests.app.mock_quote", fromlist=[""])

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization
from app.api.v1.e2ee import (
    E2EEContext,
    encrypt_for_client,
    decrypt_hex_for_model,
    ECDSA,
    ED25519,
    E2EE_VERSION_V1,
    E2EE_VERSION_V2,
)

def test_ecdsa_round_trip_v2():
    # Setup server key
    server_priv = ec.generate_private_key(ec.SECP256K1())
    server_pub_hex = server_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )[1:].hex()
    
    # Setup client key
    client_priv = ec.generate_private_key(ec.SECP256K1())
    client_pub_hex = client_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )[1:].hex()
    
    ctx = E2EEContext(
        signing_algo=ECDSA,
        client_public_key_hex=client_pub_hex,
        model_public_key_hex=server_pub_hex,
        version=E2EE_VERSION_V2,
        nonce="nonce1234567890123",
        timestamp=1700000000
    )
    
    # We need to mock _local_model_private_key to return our server_priv
    with pytest.MonkeyPatch().context() as m:
        m.setattr("app.api.v1.e2ee._local_model_private_key", lambda algo: server_priv)
        
        plaintext = "Hello World"
        aad_req = "v2|req|algo=ecdsa|model=m|m=0|c=-|n=nonce1234567890123|ts=1700000000"
        
        # 1. Encrypt for server (simulated)
        # In real app, client does this. We use decrypt_hex_for_model to test server side.
        # But we need a helper to encrypt like a client.
        
        # Reuse encrypt_for_client logic for simulation (swapping keys)
        # Actually, let's just test that decrypt_hex_for_model works with valid AAD
        # and fails with invalid AAD.
        
        # Encrypting for model (Client's perspective)
        from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from app.api.v1.e2ee import _derive_aes_key, _to_uncompressed_pubkey_bytes
        
        eph_priv = ec.generate_private_key(ec.SECP256K1())
        shared = eph_priv.exchange(ec.ECDH(), server_priv.public_key())
        aes_key = _derive_aes_key(shared, ECDSA)
        nonce = os.urandom(12)
        ct = AESGCM(aes_key).encrypt(nonce, plaintext.encode(), aad_req.encode())
        eph_pub_bytes = eph_priv.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        encrypted_hex = (eph_pub_bytes + nonce + ct).hex()
        
        # Server decrypts
        decrypted = decrypt_hex_for_model(encrypted_hex, ECDSA, aad_req)
        assert decrypted == plaintext
        
        # Test AAD failure
        with pytest.raises(Exception):
            decrypt_hex_for_model(encrypted_hex, ECDSA, aad_req + "modified")

def test_ed25519_round_trip_v2():
    # Setup server key
    server_priv = ed25519.Ed25519PrivateKey.generate()
    server_pub_hex = server_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()
    
    # Setup client key
    client_priv = ed25519.Ed25519PrivateKey.generate()
    client_pub_hex = client_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()
    
    ctx = E2EEContext(
        signing_algo=ED25519,
        client_public_key_hex=client_pub_hex,
        model_public_key_hex=server_pub_hex,
        version=E2EE_VERSION_V2,
        nonce="nonce1234567890123",
        timestamp=1700000000
    )
    
    with pytest.MonkeyPatch().context() as m:
        m.setattr("app.api.v1.e2ee._local_model_private_key", lambda algo: server_priv)
        
        plaintext = "Ed25519 Secret"
        aad_req = "v2|req|algo=ed25519|model=m|m=0|c=-|n=nonce1234567890123|ts=1700000000"
        
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from app.api.v1.e2ee import _derive_aes_key, _ed25519_public_to_x25519_public_key
        
        # Client perspective
        server_x_pub = _ed25519_public_to_x25519_public_key(server_pub_hex)
        eph_priv = x25519.X25519PrivateKey.generate()
        shared = eph_priv.exchange(server_x_pub)
        aes_key = _derive_aes_key(shared, ED25519)
        nonce = os.urandom(12)
        ct = AESGCM(aes_key).encrypt(nonce, plaintext.encode(), aad_req.encode())
        eph_pub_bytes = eph_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        encrypted_hex = (eph_pub_bytes + nonce + ct).hex()
        
        # Server decrypts
        decrypted = decrypt_hex_for_model(encrypted_hex, ED25519, aad_req)
        assert decrypted == plaintext

def test_v1_legacy_mode_ignores_aad():
    server_priv = ec.generate_private_key(ec.SECP256K1())
    server_pub_hex = server_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )[1:].hex()
    
    with pytest.MonkeyPatch().context() as m:
        m.setattr("app.api.v1.e2ee._local_model_private_key", lambda algo: server_priv)
        
        plaintext = "V1 Payload"
        
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from app.api.v1.e2ee import _derive_aes_key
        
        # Client encrypts WITHOUT AAD
        eph_priv = ec.generate_private_key(ec.SECP256K1())
        shared = eph_priv.exchange(ec.ECDH(), server_priv.public_key())
        aes_key = _derive_aes_key(shared, ECDSA)
        nonce = os.urandom(12)
        ct = AESGCM(aes_key).encrypt(nonce, plaintext.encode(), None) # No AAD
        eph_pub_bytes = eph_priv.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        encrypted_hex = (eph_pub_bytes + nonce + ct).hex()
        
        # Server decrypts in V1 mode (aad parameter provided to function but ignored internally if version=1)
        # Here we test that if we pass None to decrypt_hex_for_model, it works.
        decrypted = decrypt_hex_for_model(encrypted_hex, ECDSA, None)
        assert decrypted == plaintext
