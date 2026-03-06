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
        side_effect=ValueError("X-Model-Pub-Key does not match this proxy instance"),
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
    assert body["error"]["type"] == "invalid_e2ee_request"


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


def test_parse_e2ee_context_v2_requires_nonce_and_timestamp():
    with patch("app.api.v1.e2ee.local_model_public_key_hex", return_value="22" * 64):
        with pytest.raises(ValueError, match="requires X-E2EE-Nonce and X-E2EE-Timestamp"):
            parse_e2ee_context(
                x_signing_algo="ecdsa",
                x_client_pub_key="11" * 64,
                x_model_pub_key="22" * 64,
                x_e2ee_version="2",
                x_e2ee_nonce=None,
                x_e2ee_timestamp=None,
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

        with pytest.raises(ValueError, match="Replay detected"):
            claim_e2ee_nonce(ctx)


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
