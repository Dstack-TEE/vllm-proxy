import pytest
import httpx
from fastapi.testclient import TestClient
from unittest.mock import patch

# Standard test setup
from tests.app.test_helpers import setup_test_environment, TEST_AUTH_HEADER
setup_test_environment()

import sys
sys.modules["app.quote.quote"] = __import__("tests.app.mock_quote", fromlist=[""])

from app.main import app
from app.api.v1.openai import VLLM_METRICS_URL

client = TestClient(app)

@pytest.mark.asyncio
@pytest.mark.respx
async def test_metrics_endpoint_combined(respx_mock):
    # Mock the vLLM metrics endpoint
    vllm_metrics_content = "# HELP vllm_some_metric\n# TYPE vllm_some_metric counter\nvllm_some_metric 1.0"
    respx_mock.get(VLLM_METRICS_URL).mock(
        return_value=httpx.Response(200, text=vllm_metrics_content)
    )

    # Make request to the proxy's metrics endpoint
    response = client.get("/v1/metrics")
    
    assert response.status_code == 200
    content = response.text
    
    # Check if local metrics are present (e.g., from prometheus-fastapi-instrumentator or our custom ones)
    assert "vllm_proxy_errors_total" in content
    assert "http_requests_total" in content
    
    # Check if vLLM metrics are present
    assert "vllm_some_metric" in content
    assert "vLLM Backend Metrics" in content

@pytest.mark.asyncio
@pytest.mark.respx
async def test_metrics_endpoint_vllm_fail(respx_mock):
    # Mock the vLLM metrics endpoint to fail
    respx_mock.get(VLLM_METRICS_URL).mock(
        return_value=httpx.Response(500, text="Internal Server Error")
    )

    # Make request to the proxy's metrics endpoint
    response = client.get("/v1/metrics")
    
    assert response.status_code == 200
    content = response.text
    
    # Local metrics should still be there
    assert "vllm_proxy_errors_total" in content
    
    # Should contain error message about vLLM metrics
    assert "Failed to fetch vLLM metrics: 500" in content
