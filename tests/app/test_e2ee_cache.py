import pytest
import sys
from unittest.mock import patch, MagicMock
from tests.app.test_helpers import setup_test_environment

# Setup mocks before importing app code
setup_test_environment()
sys.modules["app.quote.quote"] = __import__("tests.app.mock_quote", fromlist=[""])

from app.api.v1.e2ee import E2EEContext, encrypt_for_client
from app.quote.quote import ECDSA

def test_encrypt_for_client_caches_keys():
    # Setup context
    ctx = E2EEContext(
        signing_algo=ECDSA,
        client_public_key_hex="11" * 64,
        model_public_key_hex="22" * 64,
        version="1",
        nonce=None,
        timestamp=None,
    )

    # First call - should generate keys and cache them
    with patch("app.api.v1.e2ee.ec.EllipticCurvePublicKey.from_encoded_point") as mock_from_point, \
         patch("app.api.v1.e2ee.ec.generate_private_key") as mock_gen_key, \
         patch("app.api.v1.e2ee._derive_aes_key", return_value=b"mock_aes_key") as mock_derive:
        
        # Setup mock for private key
        mock_private_key = MagicMock()
        mock_public_key = MagicMock()
        mock_public_key.public_bytes.return_value = b"mock_pub_bytes"
        mock_private_key.public_key.return_value = mock_public_key
        mock_private_key.exchange.return_value = b"mock_shared_secret"
        mock_gen_key.return_value = mock_private_key
        mock_from_point.return_value = mock_public_key
        
        # Need to mock AESGCM to avoid actual encryption failing with mock keys
        with patch("app.api.v1.e2ee.AESGCM") as mock_aesgcm:
            mock_aesgcm_inst = MagicMock()
            mock_aesgcm_inst.encrypt.return_value = b"ciphertext1"
            mock_aesgcm.return_value = mock_aesgcm_inst
            
            res1 = encrypt_for_client("test1", ctx)
            
            # Verify keys were generated
            assert mock_gen_key.call_count == 1
            assert mock_derive.call_count == 1
            
            # Verify context cached the keys
            assert ctx._ephemeral_public_bytes == b"mock_pub_bytes"
            assert ctx._aes_key == b"mock_aes_key"

    # Second call - should use cached keys, not generate new ones
    with patch("app.api.v1.e2ee.ec.generate_private_key") as mock_gen_key, \
         patch("app.api.v1.e2ee._derive_aes_key") as mock_derive:
        
        with patch("app.api.v1.e2ee.AESGCM") as mock_aesgcm:
            mock_aesgcm_inst = MagicMock()
            mock_aesgcm_inst.encrypt.return_value = b"ciphertext2"
            mock_aesgcm.return_value = mock_aesgcm_inst
            
            res2 = encrypt_for_client("test2", ctx)
            
            # Verify keys were NOT generated again
            assert mock_gen_key.call_count == 0
            assert mock_derive.call_count == 0
