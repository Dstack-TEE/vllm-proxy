import asyncio
import sys
import time
from dataclasses import dataclass, field
from functools import partial
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

from tests.app.test_helpers import TEST_AUTH_HEADER, setup_test_environment


setup_test_environment()
sys.modules["app.quote.quote"] = __import__("tests.app.mock_quote", fromlist=[""])

from app.main import app  # noqa: E402
from app.traffic_control import TrafficControl  # noqa: E402
from app.api.v1 import openai as openai_module  # noqa: E402


@dataclass
class MockVLLMState:
    num_requests_waiting: float = 0.0
    metrics_enabled: bool = True
    delay_seconds: float = 0.0
    chat_calls: int = 0
    completion_calls: int = 0
    last_chat_payload: dict[str, Any] | None = None
    last_completion_payload: dict[str, Any] | None = None
    seen_models: list[str] = field(default_factory=list)

    def reset(self) -> None:
        self.num_requests_waiting = 0.0
        self.metrics_enabled = True
        self.delay_seconds = 0.0
        self.chat_calls = 0
        self.completion_calls = 0
        self.last_chat_payload = None
        self.last_completion_payload = None
        self.seen_models.clear()


mock_vllm_state = MockVLLMState()
mock_vllm_app = FastAPI()


def _metrics_text() -> str:
    model = mock_vllm_state.seen_models[-1] if mock_vllm_state.seen_models else "test-model"
    return (
        "# HELP vllm:num_requests_waiting Number of requests waiting\n"
        "# TYPE vllm:num_requests_waiting gauge\n"
        f'vllm:num_requests_waiting{{engine="0",model_name="{model}"}} {mock_vllm_state.num_requests_waiting}\n'
    )


@mock_vllm_app.get("/metrics")
@mock_vllm_app.get("/v1/metrics")
async def metrics() -> PlainTextResponse:
    if not mock_vllm_state.metrics_enabled:
        return PlainTextResponse("not found", status_code=404)
    return PlainTextResponse(_metrics_text())


@mock_vllm_app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> dict[str, Any]:
    payload = await request.json()
    mock_vllm_state.chat_calls += 1
    mock_vllm_state.last_chat_payload = payload
    model = payload.get("model", "test-model")
    mock_vllm_state.seen_models.append(model)
    if mock_vllm_state.delay_seconds > 0:
        await asyncio.sleep(mock_vllm_state.delay_seconds)
    return {
        "id": f"chatcmpl-mock-{int(time.time() * 1000)}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}],
    }


@mock_vllm_app.post("/v1/completions")
async def completions(request: Request) -> dict[str, Any]:
    payload = await request.json()
    mock_vllm_state.completion_calls += 1
    mock_vllm_state.last_completion_payload = payload
    model = payload.get("model", "test-model")
    mock_vllm_state.seen_models.append(model)
    if mock_vllm_state.delay_seconds > 0:
        await asyncio.sleep(mock_vllm_state.delay_seconds)
    return {
        "id": f"cmpl-mock-{int(time.time() * 1000)}",
        "object": "text_completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "finish_reason": "stop", "text": "ok"}],
    }


@pytest.fixture
def mock_vllm_base_url(monkeypatch) -> str:
    base_url = "http://mock-vllm"
    monkeypatch.setattr(openai_module, "VLLM_BASE_URL", base_url)
    monkeypatch.setattr(openai_module, "VLLM_URL", f"{base_url}/v1/chat/completions")
    monkeypatch.setattr(openai_module, "VLLM_COMPLETIONS_URL", f"{base_url}/v1/completions")
    monkeypatch.setattr(openai_module, "VLLM_METRICS_URL", f"{base_url}/metrics")
    monkeypatch.setattr(openai_module, "VLLM_MODELS_URL", f"{base_url}/v1/models")
    return base_url


@pytest_asyncio.fixture
async def proxy_client(mock_vllm_base_url):
    mock_vllm_state.reset()
    vllm_transport = httpx.ASGITransport(app=mock_vllm_app)
    original_async_client = httpx.AsyncClient
    patched_async_client = partial(original_async_client, transport=vllm_transport)

    with patch("httpx.AsyncClient", patched_async_client):
        traffic_control = TrafficControl(mock_vllm_base_url)
        old_traffic_control = getattr(app.state, "traffic_control", None)
        app.state.traffic_control = traffic_control

        transport = httpx.ASGITransport(app=app)
        async with original_async_client(transport=transport, base_url="http://test") as client:
            yield client
        app.state.traffic_control = old_traffic_control


@pytest.mark.asyncio
async def test_basic_rejected_when_backend_busy(proxy_client):
    mock_vllm_state.num_requests_waiting = 1.0
    await app.state.traffic_control.refresh_once()

    resp = await proxy_client.post(
        "/v1/chat/completions",
        json={"model": "test-model", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": TEST_AUTH_HEADER, "X-User-Tier": "basic"},
    )

    assert resp.status_code == 429
    assert mock_vllm_state.chat_calls == 0


@pytest.mark.asyncio
async def test_missing_tier_defaults_to_basic(proxy_client):
    mock_vllm_state.num_requests_waiting = 1.0
    await app.state.traffic_control.refresh_once()

    resp = await proxy_client.post(
        "/v1/chat/completions",
        json={"model": "test-model", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": TEST_AUTH_HEADER},
    )

    assert resp.status_code == 429
    assert mock_vllm_state.chat_calls == 0


@pytest.mark.asyncio
async def test_unknown_tier_treated_as_basic(proxy_client):
    mock_vllm_state.num_requests_waiting = 1.0
    await app.state.traffic_control.refresh_once()

    resp = await proxy_client.post(
        "/v1/chat/completions",
        json={"model": "test-model", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": TEST_AUTH_HEADER, "X-User-Tier": "unknown"},
    )

    assert resp.status_code == 429
    assert mock_vllm_state.chat_calls == 0


@pytest.mark.asyncio
async def test_premium_always_passes_even_when_backend_busy(proxy_client):
    mock_vllm_state.num_requests_waiting = 1.0
    await app.state.traffic_control.refresh_once()

    resp = await proxy_client.post(
        "/v1/chat/completions",
        json={"model": "test-model", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": TEST_AUTH_HEADER, "X-User-Tier": "premium"},
    )

    assert resp.status_code == 200
    assert mock_vllm_state.chat_calls == 1


@pytest.mark.asyncio
async def test_basic_rejected_when_over_concurrency_limit(proxy_client, monkeypatch):
    mock_vllm_state.num_requests_waiting = 0.0
    mock_vllm_state.delay_seconds = 0.25
    monkeypatch.setenv("BASIC_MAX_REQUEST", "1")
    await app.state.traffic_control.refresh_once()

    payload = {"model": "test-model", "messages": [{"role": "user", "content": "hi"}]}
    headers = {"Authorization": TEST_AUTH_HEADER, "X-User-Tier": "basic"}

    t1 = asyncio.create_task(proxy_client.post("/v1/chat/completions", json=payload, headers=headers))
    await asyncio.sleep(0.05)
    t2 = asyncio.create_task(proxy_client.post("/v1/chat/completions", json=payload, headers=headers))
    r1, r2 = await asyncio.gather(t1, t2)

    assert sorted([r1.status_code, r2.status_code]) == [200, 429]
    assert mock_vllm_state.chat_calls == 1


@pytest.mark.asyncio
async def test_traffic_control_applies_to_completions(proxy_client):
    mock_vllm_state.num_requests_waiting = 1.0
    await app.state.traffic_control.refresh_once()

    resp = await proxy_client.post(
        "/v1/completions",
        json={"model": "test-model", "prompt": "hi"},
        headers={"Authorization": TEST_AUTH_HEADER, "X-User-Tier": "basic"},
    )

    assert resp.status_code == 429
    assert mock_vllm_state.completion_calls == 0


@pytest.mark.asyncio
async def test_fail_open_when_metrics_unknown(proxy_client):
    mock_vllm_state.num_requests_waiting = 1.0
    resp = await proxy_client.post(
        "/v1/chat/completions",
        json={"model": "test-model", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": TEST_AUTH_HEADER, "X-User-Tier": "basic"},
    )

    assert resp.status_code == 200
    assert mock_vllm_state.chat_calls == 1


@pytest.mark.asyncio
async def test_fail_open_when_no_metrics_endpoint(proxy_client):
    mock_vllm_state.metrics_enabled = False
    mock_vllm_state.num_requests_waiting = 1.0
    await app.state.traffic_control.refresh_once()

    resp = await proxy_client.post(
        "/v1/chat/completions",
        json={"model": "test-model", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": TEST_AUTH_HEADER, "X-User-Tier": "basic"},
    )

    assert resp.status_code == 200
    assert mock_vllm_state.chat_calls == 1


@pytest.mark.asyncio
async def test_fail_open_when_metrics_stale(proxy_client, monkeypatch):
    mock_vllm_state.num_requests_waiting = 1.0
    await app.state.traffic_control.refresh_once()

    monkeypatch.setattr(app.state.traffic_control, "_busy", True)
    monkeypatch.setattr(app.state.traffic_control, "_last_ok_monotonic", time.monotonic() - 3600)

    resp = await proxy_client.post(
        "/v1/chat/completions",
        json={"model": "test-model", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": TEST_AUTH_HEADER, "X-User-Tier": "basic"},
    )

    assert resp.status_code == 200
    assert mock_vllm_state.chat_calls == 1
