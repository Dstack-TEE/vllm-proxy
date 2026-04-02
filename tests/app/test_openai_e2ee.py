import base64
import hashlib
import json

import httpx
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from tests.app.test_helpers import setup_test_environment, TEST_AUTH_HEADER

setup_test_environment()

import sys

sys.modules["app.quote.quote"] = __import__("tests.app.mock_quote", fromlist=[""])

from app.main import app
from app.api.v1.openai import VLLM_URL, VLLM_COMPLETIONS_URL
from app.api.v1.e2ee import (
    E2EEContext,
    E2EEReplayDetectedError,
    E2EEInvalidVersionError,
    E2EEInvalidNonceError,
    E2EEModelKeyMismatchError,
    E2EEHeaderMissingError,
    claim_e2ee_nonce,
    decrypt_request_json,
    parse_e2ee_context,
)

client = TestClient(app)


@pytest.mark.asyncio
@pytest.mark.respx
async def test_chat_completions_e2ee_non_streaming(respx_mock):
    request_data = {
        "model": "test-model",
        "messages": [{"role": "user", "content": "encrypted-hex"}],
        "stream": False,
    }

    route = respx_mock.post(VLLM_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "chatcmpl-e2ee",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "plaintext-response"},
                        "finish_reason": "stop",
                    }
                ],
            },
        )
    )

    e2ee_ctx = E2EEContext(
        signing_algo="ecdsa",
        client_public_key_hex="11" * 64,
        model_public_key_hex="22" * 64,
        version="1",
        nonce=None,
        timestamp=None,
    )

    with patch("app.api.v1.openai.parse_e2ee_context", return_value=e2ee_ctx), patch(
        "app.api.v1.openai.decrypt_request_json",
        return_value={
            "model": "test-model",
            "messages": [{"role": "user", "content": "decrypted-prompt"}],
            "stream": False,
        },
    ), patch(
        "app.api.v1.openai.encrypt_chat_completion_response",
        side_effect=lambda data, _: {
            **data,
            "choices": [
                {
                    **data["choices"][0],
                    "message": {
                        "role": "assistant",
                        "content": "encrypted-response-hex",
                    },
                }
            ],
        },
    ):
        response = client.post(
            "/v1/chat/completions",
            json=request_data,
            headers={
                "Authorization": TEST_AUTH_HEADER,
                "X-Signing-Algo": "ecdsa",
                "X-Client-Pub-Key": "11" * 64,
                "X-Model-Pub-Key": "22" * 64,
            },
        )

    assert response.status_code == 200
    assert route.called
    sent_json = route.calls[0].request.read().decode("utf-8")
    assert "decrypted-prompt" in sent_json
    assert response.json()["choices"][0]["message"]["content"] == "encrypted-response-hex"


@pytest.mark.asyncio
async def test_chat_completions_e2ee_invalid_headers_returns_400():
    request_data = {
        "model": "test-model",
        "messages": [{"role": "user", "content": "foo"}],
        "stream": False,
    }

    with patch(
        "app.api.v1.openai.parse_e2ee_context",
        side_effect=E2EEModelKeyMismatchError("X-Model-Pub-Key does not match this proxy instance"),
    ):
        response = client.post(
            "/v1/chat/completions",
            json=request_data,
            headers={
                "Authorization": TEST_AUTH_HEADER,
                "X-Signing-Algo": "ecdsa",
                "X-Client-Pub-Key": "11" * 64,
                "X-Model-Pub-Key": "22" * 64,
            },
        )

    assert response.status_code == 400
    body = response.json()
    assert body["error"]["type"] == "e2ee_model_key_mismatch"


@pytest.mark.asyncio
async def test_completions_rejects_e2ee_headers():
    request_data = {"model": "test-model", "prompt": "Hello", "stream": False}

    response = client.post(
        "/v1/completions",
        json=request_data,
        headers={
            "Authorization": TEST_AUTH_HEADER,
            "X-Signing-Algo": "ecdsa",
            "X-Client-Pub-Key": "11" * 64,
            "X-Model-Pub-Key": "22" * 64,
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["message"] == "E2EE is only supported on /v1/chat/completions"


def test_decrypt_request_json_supports_multimodal_text_items():
    payload = {
        "model": "test-model",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "aa" * 40},
                    {"type": "image_url", "image_url": {"url": "https://example.com/x.png"}},
                ],
            }
        ],
    }

    with patch("app.api.v1.e2ee.decrypt_hex_for_model", return_value="hello"):
        out = decrypt_request_json(
            payload, E2EEContext("ecdsa", "11" * 64, "22" * 64, "1", None, None)
        )

    assert out["messages"][0]["content"][0]["text"] == "hello"
    assert out["messages"][0]["content"][1]["type"] == "image_url"


def test_decrypt_request_json_does_not_mutate_input_payload():
    original = {
        "messages": [{"role": "user", "content": "aa" * 40}],
    }
    payload = {
        "messages": [{"role": "user", "content": "aa" * 40}],
    }

    with patch("app.api.v1.e2ee.decrypt_hex_for_model", return_value="plain"):
        out = decrypt_request_json(
            payload, E2EEContext("ecdsa", "11" * 64, "22" * 64, "1", None, None)
        )

    assert payload == original
    assert out["messages"][0]["content"] == "plain"


def test_decrypt_request_json_supports_stringified_multimodal_content_array():
    payload = {
        "messages": [{"role": "user", "content": "aa" * 40}],
    }
    decrypted_multimodal = '[{"type":"text","text":"hello"},{"type":"image_url","image_url":{"url":"https://example.com/x.png"}}]'

    with patch("app.api.v1.e2ee.decrypt_hex_for_model", return_value=decrypted_multimodal):
        out = decrypt_request_json(
            payload, E2EEContext("ecdsa", "11" * 64, "22" * 64, "1", None, None)
        )

    assert isinstance(out["messages"][0]["content"], list)
    assert out["messages"][0]["content"][0]["type"] == "text"
    assert out["messages"][0]["content"][1]["type"] == "image_url"


def test_decrypt_request_json_keeps_non_list_json_string_as_plain_text():
    payload = {
        "messages": [{"role": "user", "content": "aa" * 40}],
    }

    with patch("app.api.v1.e2ee.decrypt_hex_for_model", return_value='{"foo":"bar"}'):
        out = decrypt_request_json(
            payload, E2EEContext("ecdsa", "11" * 64, "22" * 64, "1", None, None)
        )

    assert out["messages"][0]["content"] == '{"foo":"bar"}'


def test_parse_e2ee_context_v2_requires_nonce_and_timestamp():
    with patch("app.api.v1.e2ee.local_model_public_key_hex", return_value="22" * 64):
        with pytest.raises(E2EEHeaderMissingError, match="requires X-E2EE-Nonce and X-E2EE-Timestamp"):
            parse_e2ee_context(
                x_signing_algo="ecdsa",
                x_client_pub_key="11" * 64,
                x_model_pub_key="22" * 64,
                x_e2ee_version="2",
                x_e2ee_nonce=None,
                x_e2ee_timestamp=None,
            )
        
        with pytest.raises(E2EEInvalidNonceError, match="must be at least 16 characters"):
            parse_e2ee_context(
                x_signing_algo="ecdsa",
                x_client_pub_key="11" * 64,
                x_model_pub_key="22" * 64,
                x_e2ee_version="2",
                x_e2ee_nonce="short",
                x_e2ee_timestamp="1700000000",
            )


def test_parse_e2ee_context_v2_replay_protection():
    now_ts = "1700000000"
    with patch("app.api.v1.e2ee.local_model_public_key_hex", return_value="22" * 64), patch(
        "app.api.v1.e2ee.replay_cache.validate_timestamp_window", return_value=True
    ), patch("app.api.v1.e2ee.replay_cache.claim", side_effect=[True, False]):
        ctx = parse_e2ee_context(
            x_signing_algo="ecdsa",
            x_client_pub_key="11" * 64,
            x_model_pub_key="22" * 64,
            x_e2ee_version="2",
            x_e2ee_nonce="abcd1234abcd1234",
            x_e2ee_timestamp=now_ts,
        )
        assert ctx.version == "2"
        assert ctx.timestamp == 1700000000
        claim_e2ee_nonce(ctx)

        with pytest.raises(E2EEReplayDetectedError, match="Replay detected"):
            claim_e2ee_nonce(ctx)


def test_parse_e2ee_context_implicit_v2_when_nonce_and_timestamp_present():
    with patch("app.api.v1.e2ee.local_model_public_key_hex", return_value="22" * 64):
        ctx = parse_e2ee_context(
            x_signing_algo="ecdsa",
            x_client_pub_key="11" * 64,
            x_model_pub_key="22" * 64,
            x_e2ee_version=None,
            x_e2ee_nonce="abcd1234abcd1234",
            x_e2ee_timestamp="1700000000",
        )
    assert ctx.version == "2"
    assert ctx.timestamp == 1700000000


def test_parse_e2ee_context_legacy_mode_when_nonce_and_timestamp_absent():
    with patch("app.api.v1.e2ee.local_model_public_key_hex", return_value="22" * 64):
        ctx = parse_e2ee_context(
            x_signing_algo="ecdsa",
            x_client_pub_key="11" * 64,
            x_model_pub_key="22" * 64,
            x_e2ee_version=None,
            x_e2ee_nonce=None,
            x_e2ee_timestamp=None,
        )
    assert ctx.version == "1"
    assert ctx.timestamp is None


def test_parse_e2ee_context_rejects_partial_nonce_timestamp_pair():
    with patch("app.api.v1.e2ee.local_model_public_key_hex", return_value="22" * 64):
        with pytest.raises(E2EEHeaderMissingError, match="must be provided together"):
            parse_e2ee_context(
                x_signing_algo="ecdsa",
                x_client_pub_key="11" * 64,
                x_model_pub_key="22" * 64,
                x_e2ee_version=None,
                x_e2ee_nonce="abcd1234abcd1234",
                x_e2ee_timestamp=None,
            )


def test_parse_e2ee_context_allows_ed25519():
    pub = "33" * 32
    with patch("app.api.v1.e2ee.local_model_public_key_hex", return_value=pub):
        ctx = parse_e2ee_context(
            x_signing_algo="ed25519",
            x_client_pub_key=pub,
            x_model_pub_key=pub,
        )
    assert ctx is not None
    assert ctx.signing_algo == "ed25519"


def test_attestation_report_includes_signing_public_key():
    # Test ECDSA
    response = client.get("/v1/attestation/report?signing_algo=ecdsa", headers={"Authorization": TEST_AUTH_HEADER})
    assert response.status_code == 200
    data = response.json()
    assert "signing_public_key" in data
    assert len(data["signing_public_key"]) == 128
    assert data["all_attestations"][0]["signing_public_key"] == data["signing_public_key"]

    # Test Ed25519
    response = client.get("/v1/attestation/report?signing_algo=ed25519", headers={"Authorization": TEST_AUTH_HEADER})
    assert response.status_code == 200
    data = response.json()
    assert "signing_public_key" in data
    assert len(data["signing_public_key"]) == 64
    assert data["all_attestations"][0]["signing_public_key"] == data["signing_public_key"]


def _make_chutes_quote_b64(nonce: str, e2e_pubkey: str, *, debug_enabled: bool = False) -> str:
    quote_bytes = bytearray(700)

    td_attributes_offset = 48 + 120
    quote_bytes[td_attributes_offset : td_attributes_offset + 8] = (1 if debug_enabled else 0).to_bytes(8, "little")

    report_data_offset = 48 + 520
    report_data_hex = hashlib.sha256((nonce + e2e_pubkey).encode("utf-8")).hexdigest()
    report_data_bytes = bytes.fromhex(report_data_hex) + bytes(32)
    quote_bytes[report_data_offset : report_data_offset + 64] = report_data_bytes

    return base64.b64encode(bytes(quote_bytes)).decode("utf-8")


@pytest.mark.asyncio
@pytest.mark.respx
async def test_attestation_chain_success_proxy_mode(respx_mock):
    model = "moonshotai/Kimi-K2.5-TEE"
    nonce = "a" * 16
    e2e_pubkey = "pk-1"
    quote_b64 = _make_chutes_quote_b64(nonce, e2e_pubkey)

    respx_mock.get("https://api.chutes.ai/chutes/").mock(
        return_value=httpx.Response(200, json={"items": [{"chute_id": "chute-123"}]})
    )
    respx_mock.get("https://api.chutes.ai/e2e/instances/chute-123").mock(
        return_value=httpx.Response(
            200,
            json={"instances": [{"instance_id": "inst-1", "e2e_pubkey": e2e_pubkey}]},
        )
    )
    respx_mock.get("https://api.chutes.ai/chutes/chute-123/evidence").mock(
        return_value=httpx.Response(
            200,
            json={
                "evidence": [
                    {
                        "instance_id": "inst-1",
                        "quote": quote_b64,
                        "tdx_verification": {"result": {"status": "UpToDate"}},
                        "certificate": "cert",
                    }
                ]
            },
        )
    )

    with patch("app.api.v1.openai.CHUTES_ENABLED", True), patch("app.api.v1.openai.CHUTES_API_KEY", "test-key"):
        response = client.get(
            "/v1/attestation/chain",
            params={"model": model, "nonce": nonce, "signing_algo": "ecdsa"},
            headers={"Authorization": TEST_AUTH_HEADER},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["version"] == "1"
    assert data["verify_mode"] == "proxy"
    assert data["proxy"]["attestation"]["request_nonce"] == nonce
    assert "verification_receipt" in data
    assert data["verification_receipt"]["payload"]["result"] == "pass"
    assert data["verification_receipt"]["payload"]["model"] == model


@pytest.mark.asyncio
@pytest.mark.respx
async def test_attestation_chain_passthrough_mode_returns_upstream_bundle(respx_mock):
    model = "moonshotai/Kimi-K2.5-TEE"
    nonce = "b" * 16
    e2e_pubkey = "pk-2"
    quote_b64 = _make_chutes_quote_b64(nonce, e2e_pubkey)

    respx_mock.get("https://api.chutes.ai/chutes/").mock(
        return_value=httpx.Response(200, json={"items": [{"chute_id": "chute-321"}]})
    )
    respx_mock.get("https://api.chutes.ai/e2e/instances/chute-321").mock(
        return_value=httpx.Response(
            200,
            json={"instances": [{"instance_id": "inst-2", "e2e_pubkey": e2e_pubkey}]},
        )
    )
    respx_mock.get("https://api.chutes.ai/chutes/chute-321/evidence").mock(
        return_value=httpx.Response(
            200,
            json={
                "evidence": [
                    {
                        "instance_id": "inst-2",
                        "quote": quote_b64,
                        "tdx_verification": {"result": {"status": "UpToDate"}},
                        "certificate": "cert",
                    }
                ]
            },
        )
    )

    with patch("app.api.v1.openai.CHUTES_ENABLED", True), patch("app.api.v1.openai.CHUTES_API_KEY", "test-key"):
        response = client.get(
            "/v1/attestation/chain",
            params={"model": model, "nonce": nonce, "signing_algo": "ecdsa", "verify_mode": "passthrough"},
            headers={"Authorization": TEST_AUTH_HEADER},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["verify_mode"] == "passthrough"
    expected_hash = hashlib.sha256(
        json.dumps(data["upstream"]["attestation"], sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert data["upstream"]["attestation_sha256"] == expected_hash
    assert data["binding_proof"]["payload"]["upstream_attestation_sha256"] == expected_hash


def test_attestation_chain_proxy_mode_verification_failure_returns_502():
    model = "moonshotai/Kimi-K2.5-TEE"
    nonce = "a" * 16

    with patch("app.api.v1.openai.CHUTES_ENABLED", True), patch("app.api.v1.openai.CHUTES_API_KEY", "test-key"), patch(
        "app.api.v1.openai._fetch_chutes_attestation",
        return_value=(
            {
                "attestation_type": "chutes",
                "nonce": nonce,
                "chute_id": "chute-123",
                "all_attestations": [
                    {
                        "instance_id": "inst-1",
                        "e2e_pubkey": "pk-1",
                        "intel_quote": "bad-quote",
                        "tdx_verification": {"result": {"status": "OutOfDate"}},
                    }
                ],
            },
            None,
        ),
    ):
        response = client.get(
            "/v1/attestation/chain",
            params={"model": model, "nonce": nonce, "signing_algo": "ecdsa"},
            headers={"Authorization": TEST_AUTH_HEADER},
        )

    assert response.status_code == 502
    assert response.json()["error"]["type"] == "chutes_verification_failed"


def test_attestation_chain_nonce_too_short():
    with patch("app.api.v1.openai.CHUTES_ENABLED", True), patch("app.api.v1.openai.CHUTES_API_KEY", "test-key"):
        response = client.get(
            "/v1/attestation/chain",
            params={"model": "moonshotai/Kimi-K2.5-TEE", "nonce": "short", "signing_algo": "ecdsa"},
            headers={"Authorization": TEST_AUTH_HEADER},
        )

    assert response.status_code == 400
    assert response.json()["error"]["type"] == "invalid_nonce"


def test_attestation_chain_proxy_mode_rejects_tdx_online_verification_error():
    model = "moonshotai/Kimi-K2.5-TEE"
    nonce = "c" * 16

    with patch("app.api.v1.openai.CHUTES_ENABLED", True), patch("app.api.v1.openai.CHUTES_API_KEY", "test-key"), patch(
        "app.api.v1.openai._fetch_chutes_attestation",
        return_value=(
            {
                "attestation_type": "chutes",
                "nonce": nonce,
                "chute_id": "chute-123",
                "all_attestations": [
                    {
                        "instance_id": "inst-1",
                        "e2e_pubkey": "pk-1",
                        "intel_quote": _make_chutes_quote_b64(nonce, "pk-1"),
                        "tdx_verification": {"error": "upstream verifier timeout", "result": {"status": "UpToDate"}},
                    }
                ],
            },
            None,
        ),
    ):
        response = client.get(
            "/v1/attestation/chain",
            params={"model": model, "nonce": nonce, "signing_algo": "ecdsa"},
            headers={"Authorization": TEST_AUTH_HEADER},
        )

    assert response.status_code == 502
    assert response.json()["error"]["type"] == "chutes_verification_failed"


def test_attestation_chain_invalid_verify_mode():
    with patch("app.api.v1.openai.CHUTES_ENABLED", True), patch("app.api.v1.openai.CHUTES_API_KEY", "test-key"):
        response = client.get(
            "/v1/attestation/chain",
            params={"model": "moonshotai/Kimi-K2.5-TEE", "nonce": "a" * 16, "signing_algo": "ecdsa", "verify_mode": "bad"},
            headers={"Authorization": TEST_AUTH_HEADER},
        )

    assert response.status_code == 400
    assert response.json()["error"]["type"] == "invalid_verify_mode"


def test_attestation_chain_model_empty():
    with patch("app.api.v1.openai.CHUTES_ENABLED", True), patch("app.api.v1.openai.CHUTES_API_KEY", "test-key"):
        response = client.get(
            "/v1/attestation/chain",
            params={"model": "   ", "nonce": "a" * 16, "signing_algo": "ecdsa"},
            headers={"Authorization": TEST_AUTH_HEADER},
        )

    assert response.status_code == 400
    assert response.json()["error"]["type"] == "invalid_model"
