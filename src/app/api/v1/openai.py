import json
import os
import time
import hashlib
from hashlib import sha256
from typing import Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Header, Query
from fastapi.responses import (
    JSONResponse,
    PlainTextResponse,
    StreamingResponse,
    Response,
)

from app.api.helper.auth import verify_authorization_header
from app.api.response.response import (
    error,
    invalid_signing_algo,
    not_found,
    unexpect_error,
)
from app.api.v1.e2ee import (
    E2EEError,
    claim_e2ee_nonce,
    decrypt_request_json,
    encrypt_chat_completion_chunk,
    encrypt_chat_completion_response,
    get_e2ee_response_headers,
    local_model_public_key_hex,
    parse_e2ee_context,
)
from app.cache.cache import cache
from app.logger import log
from app.metrics import get_proxy_metrics
from app.quote.quote import (
    ECDSA,
    ED25519,
    ecdsa_context,
    ed25519_context,
    generate_attestation,
    sign_message,
)

router = APIRouter(tags=["openai"])

VLLM_BASE_URL = os.getenv("VLLM_BASE_URL", "http://vllm:8000")
VLLM_URL = f"{VLLM_BASE_URL}/v1/chat/completions"
VLLM_COMPLETIONS_URL = f"{VLLM_BASE_URL}/v1/completions"
VLLM_METRICS_URL = f"{VLLM_BASE_URL}/metrics"
VLLM_MODELS_URL = f"{VLLM_BASE_URL}/v1/models"

CHUTES_ENABLED = os.getenv("CHUTES_ENABLED", "false").lower() in ("1", "true", "yes", "on")
CHUTES_BASE_URL = os.getenv("CHUTES_BASE_URL", "https://llm.chutes.ai").rstrip("/")
CHUTES_CHAT_COMPLETIONS_URL = f"{CHUTES_BASE_URL}/v1/chat/completions"
CHUTES_MODELS_URL = f"{CHUTES_BASE_URL}/v1/models"
CHUTES_API_KEY = os.getenv("CHUTES_API_KEY")

TIMEOUT = 60 * 10

COMMON_HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}


def sign_request(request: dict, response: str):
    content = json.dumps(request.get("messages", [])) + "\n" + response
    return quote.sign(content)


def hash(payload: str):
    return sha256(payload.encode()).hexdigest()


def sign_chat(text: str):
    return dict(
        text=text,
        signature_ecdsa=sign_message(ecdsa_context, text),
        signing_address_ecdsa=ecdsa_context.signing_address,
        signature_ed25519=sign_message(ed25519_context, text),
        signing_address_ed25519=ed25519_context.signing_address,
    )


def _with_outbound_headers(outbound_headers: Optional[dict[str, str]] = None) -> dict[str, str]:
    headers = dict(COMMON_HEADERS)
    if outbound_headers:
        headers.update(outbound_headers)
    return headers


def _chutes_auth_headers() -> dict[str, str]:
    if CHUTES_API_KEY:
        return {"Authorization": f"Bearer {CHUTES_API_KEY}"}
    return {}


async def stream_vllm_response(
    url: str,
    request_body: bytes,
    modified_request_body: bytes,
    request_hash: Optional[str] = None,
    e2ee_ctx=None,
    outbound_headers: Optional[dict[str, str]] = None,
    model_name: Optional[str] = None,
):
    """
    Handle streaming backend request.
    Args:
        request_body: The original request body
        modified_request_body: The modified enhanced request body
        request_hash: Optional hash from request header (X-Request-Hash). Used by trusted clients to provide
                     pre-calculated request hash, avoiding redundant hash computation. Falls back to
                     calculating hash from request_body if not provided
    Returns:
        A streaming response
    """
    if request_hash:
        request_sha256 = request_hash
        log.info(f"Using client-provided request hash: {request_sha256}")
    else:
        request_sha256 = sha256(request_body).hexdigest()
        log.debug(f"Calculated request hash: {request_sha256}")

    chat_id = None
    h = sha256()

    async def generate_stream(response):
        nonlocal chat_id, h
        async for line in response.aiter_lines():
            final_chunk = line + "\n"

            if line.startswith("data: "):
                data = line[6:].strip()
                if data and data != "[DONE]":
                    try:
                        chunk_data = json.loads(data)

                        # Extract the cache key (data.id) from the first chunk
                        if not chat_id:
                            chat_id = chunk_data.get("id")

                        chunk_data = encrypt_chat_completion_chunk(chunk_data, e2ee_ctx)
                        final_chunk = f"data: {json.dumps(chunk_data)}\n\n"

                    except Exception as e:
                        error_message = f"Failed to parse chunk: {e}\n The original data is: {data}"
                        log.error(error_message)
                        if not chat_id:
                             raise Exception(error_message)
            h.update(final_chunk.encode())
            yield final_chunk

        response_sha256 = h.hexdigest()
        # Cache the full request and response using the extracted cache key
        if chat_id:
            cache.set_chat(
                chat_id,
                json.dumps(sign_chat(f"{request_sha256}:{response_sha256}")),
                model_name=model_name,
            )
        else:
            error_message = "Chat id could not be extracted from the response"
            log.error(error_message)
            raise Exception(error_message)

    client = httpx.AsyncClient(
        timeout=httpx.Timeout(TIMEOUT),
        headers=_with_outbound_headers(outbound_headers),
    )
    req = client.build_request("POST", url, content=modified_request_body)
    response = await client.send(req, stream=True)
    # If not 200, return the error response directly without streaming
    if response.status_code != 200:
        error_content = await response.aread()
        await response.aclose()
        await client.aclose()

        return Response(
            content=error_content,
            status_code=response.status_code,
            headers=response.headers,
        )

    return StreamingResponse(
        generate_stream(response),
        background=BackgroundTasks([response.aclose, client.aclose]),
        media_type="text/event-stream",
        headers={
            "X-Accel-Buffering": "no",
            **get_e2ee_response_headers(e2ee_ctx),
        },
    )


# Function to handle non-streaming responses
async def non_stream_vllm_response(
    url: str,
    request_body: bytes,
    modified_request_body: bytes,
    request_hash: Optional[str] = None,
    e2ee_ctx=None,
    outbound_headers: Optional[dict[str, str]] = None,
    model_name: Optional[str] = None,
):
    """
    Handle non-streaming responses
    Args:
        request_body: The original request body
        modified_request_body: The modified enhanced request body
        request_hash: Optional hash from request header (X-Request-Hash). Used by trusted clients to provide
                     pre-calculated request hash, avoiding redundant hash computation. Falls back to
                     calculating hash from request_body if not provided
    Returns:
        The response data
    """
    if request_hash:
        request_sha256 = request_hash
        log.info(f"Using client-provided request hash: {request_sha256}")
    else:
        request_sha256 = sha256(request_body).hexdigest()
        log.debug(f"Calculated request hash: {request_sha256}")

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(TIMEOUT),
        headers=_with_outbound_headers(outbound_headers),
    ) as client:
        response = await client.post(url, content=modified_request_body)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)

        response_data = response.json()
        response_data = encrypt_chat_completion_response(response_data, e2ee_ctx)

        # Cache the request-response pair using the chat ID
        chat_id = response_data.get("id")
        if chat_id:
            response_sha256 = sha256(json.dumps(response_data).encode("utf-8")).hexdigest()
            cache.set_chat(
                chat_id,
                json.dumps(sign_chat(f"{request_sha256}:{response_sha256}")),
                model_name=model_name,
            )
        else:
            raise Exception("Chat id could not be extracted from the response")

        return response_data


def strip_empty_tool_calls(payload: dict) -> dict:
    """
    Strip empty tool calls from the payload
    To fix the bug of:
    https://github.com/vllm-project/vllm/pull/14054
    """
    if "messages" not in payload:
        return payload

    filtered_messages = []
    for message in payload["messages"]:
        # If the message has tool_calls, filter out empty ones
        if (
            "tool_calls" in message
            and isinstance(message["tool_calls"], list)
            and len(message["tool_calls"]) == 0
        ):
            del message["tool_calls"]
        filtered_messages.append(message)

    payload["messages"] = filtered_messages
    return payload


def _normalize_signing_algo(signing_algo: str | None) -> str:
    algo = ECDSA if signing_algo is None else signing_algo.strip().lower()
    if algo not in [ECDSA, ED25519]:
        raise ValueError("invalid_signing_algo")
    return algo


def _build_proxy_attestation(signing_algo: str, nonce: str | None) -> dict:
    context = ecdsa_context if signing_algo == ECDSA else ed25519_context
    attestation = dict(generate_attestation(context, nonce))
    attestation["signing_public_key"] = local_model_public_key_hex(signing_algo)

    resp = dict(attestation)
    resp["signing_public_key"] = attestation["signing_public_key"]
    resp["all_attestations"] = [attestation]
    return resp


# Get attestation report of intel quote and nvidia payload
@router.get("/attestation/report", dependencies=[Depends(verify_authorization_header)])
async def attestation_report(
    request: Request,
    signing_algo: str | None = None,
    nonce: str | None = Query(None),
    signing_address: str | None = Query(None),
):
    try:
        algo = _normalize_signing_algo(signing_algo)
    except ValueError:
        return invalid_signing_algo()

    try:
        return _build_proxy_attestation(algo, nonce)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/attestation/chain", dependencies=[Depends(verify_authorization_header)])
async def attestation_chain(
    request: Request,
    model: str = Query(...),
    nonce: str = Query(...),
    signing_algo: str | None = None,
):
    if not CHUTES_ENABLED:
        return error(status_code=503, message="Chutes route is disabled", type="chutes_disabled")

    if not CHUTES_API_KEY:
        return error(status_code=503, message="CHUTES_API_KEY is not configured", type="chutes_misconfigured")

    try:
        algo = _normalize_signing_algo(signing_algo)
    except ValueError:
        return invalid_signing_algo()

    nonce = nonce.strip()
    model = model.strip()
    if len(nonce) < 16:
        return error(
            status_code=400,
            message="nonce must be at least 16 characters",
            type="invalid_nonce",
        )
    if not model:
        return error(status_code=400, message="model must not be empty", type="invalid_model")

    try:
        proxy_attestation = _build_proxy_attestation(algo, nonce)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    upstream_params = {"model": model, "nonce": nonce, "signing_algo": algo}
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(TIMEOUT),
            headers=_with_outbound_headers(_chutes_auth_headers()),
        ) as client:
            upstream_response = await client.get(
                f"{CHUTES_BASE_URL}/v1/attestation/report",
                params=upstream_params,
            )
    except httpx.RequestError as exc:
        return error(status_code=502, message=f"Failed to fetch upstream attestation: {exc}", type="upstream_unreachable")

    if upstream_response.status_code != 200:
        raise HTTPException(status_code=upstream_response.status_code, detail=upstream_response.text)

    try:
        upstream_attestation = upstream_response.json()
    except ValueError:
        return error(status_code=502, message="Upstream attestation response is not valid JSON", type="upstream_invalid_response")
    upstream_raw = json.dumps(upstream_attestation, sort_keys=True, separators=(",", ":"))
    upstream_attestation_sha256 = hashlib.sha256(upstream_raw.encode("utf-8")).hexdigest()

    binding_payload = {
        "nonce": nonce,
        "timestamp": int(time.time()),
        "provider": "chutes",
        "upstream_base_url": CHUTES_BASE_URL,
        "model": model,
        "upstream_attestation_sha256": upstream_attestation_sha256,
    }
    binding_text = json.dumps(binding_payload, sort_keys=True, separators=(",", ":"))
    context = ecdsa_context if algo == ECDSA else ed25519_context

    return {
        "version": "1",
        "proxy": {
            "attestation": proxy_attestation,
            "signing_public_key": proxy_attestation.get("signing_public_key"),
        },
        "upstream": {
            "provider": "chutes",
            "base_url": CHUTES_BASE_URL,
            "model": model,
            "attestation": upstream_attestation,
            "attestation_sha256": upstream_attestation_sha256,
        },
        "binding_proof": {
            "payload": binding_payload,
            "signature": sign_message(context, binding_text),
            "signing_algo": algo,
            "signing_address": context.signing_address,
        },
    }


async def _chat_completions_impl(
    request: Request,
    x_request_hash: Optional[str],
    x_signing_algo: Optional[str],
    x_client_pub_key: Optional[str],
    x_model_pub_key: Optional[str],
    x_e2ee_version: Optional[str],
    x_e2ee_nonce: Optional[str],
    x_e2ee_timestamp: Optional[str],
    backend_url: str,
    outbound_headers: Optional[dict[str, str]] = None,
):
    # Keep original request body to calculate the request hash for attestation
    request_body = await request.body()
    request_json = json.loads(request_body)

    try:
        e2ee_ctx = parse_e2ee_context(
            x_signing_algo=x_signing_algo,
            x_client_pub_key=x_client_pub_key,
            x_model_pub_key=x_model_pub_key,
            x_e2ee_version=x_e2ee_version,
            x_e2ee_nonce=x_e2ee_nonce,
            x_e2ee_timestamp=x_e2ee_timestamp,
        )
        request_json = decrypt_request_json(request_json, e2ee_ctx)
        if e2ee_ctx:
            claim_e2ee_nonce(e2ee_ctx)
    except E2EEError as exc:
        return error(status_code=400, message=str(exc), type=exc.error_type)
    except ValueError as exc:
        return error(status_code=400, message=str(exc), type="invalid_e2ee_request")

    modified_json = strip_empty_tool_calls(request_json)

    # Check if the request is for streaming or non-streaming
    is_stream = modified_json.get("stream", False)
    request_model = modified_json.get("model")
    modified_request_body = json.dumps(modified_json).encode("utf-8")

    if is_stream:
        return await stream_vllm_response(
            backend_url,
            request_body,
            modified_request_body,
            x_request_hash,
            e2ee_ctx,
            outbound_headers=outbound_headers,
            model_name=request_model,
        )

    response_data = await non_stream_vllm_response(
        backend_url,
        request_body,
        modified_request_body,
        x_request_hash,
        e2ee_ctx,
        outbound_headers=outbound_headers,
        model_name=request_model,
    )
    return JSONResponse(
        content=response_data,
        headers=get_e2ee_response_headers(e2ee_ctx),
    )


# Chat completions (compat route):
# - CHUTES_ENABLED=false -> original vLLM backend behavior
# - CHUTES_ENABLED=true  -> transparently route to Chutes backend
@router.post("/chat/completions", dependencies=[Depends(verify_authorization_header)])
async def chat_completions(
    request: Request,
    x_request_hash: Optional[str] = Header(None, alias="X-Request-Hash"),
    x_signing_algo: Optional[str] = Header(None, alias="X-Signing-Algo"),
    x_client_pub_key: Optional[str] = Header(None, alias="X-Client-Pub-Key"),
    x_model_pub_key: Optional[str] = Header(None, alias="X-Model-Pub-Key"),
    x_e2ee_version: Optional[str] = Header(None, alias="X-E2EE-Version"),
    x_e2ee_nonce: Optional[str] = Header(None, alias="X-E2EE-Nonce"),
    x_e2ee_timestamp: Optional[str] = Header(None, alias="X-E2EE-Timestamp"),
):
    backend_url = VLLM_URL
    outbound_headers = None

    if CHUTES_ENABLED:
        if not CHUTES_API_KEY:
            return error(status_code=503, message="CHUTES_API_KEY is not configured", type="chutes_misconfigured")
        backend_url = CHUTES_CHAT_COMPLETIONS_URL
        outbound_headers = _chutes_auth_headers()

    return await _chat_completions_impl(
        request=request,
        x_request_hash=x_request_hash,
        x_signing_algo=x_signing_algo,
        x_client_pub_key=x_client_pub_key,
        x_model_pub_key=x_model_pub_key,
        x_e2ee_version=x_e2ee_version,
        x_e2ee_nonce=x_e2ee_nonce,
        x_e2ee_timestamp=x_e2ee_timestamp,
        backend_url=backend_url,
        outbound_headers=outbound_headers,
    )


# Chutes chat completions (new path, side-by-side with existing logic)
@router.post("/chutes/chat/completions", dependencies=[Depends(verify_authorization_header)])
async def chutes_chat_completions(
    request: Request,
    x_request_hash: Optional[str] = Header(None, alias="X-Request-Hash"),
    x_signing_algo: Optional[str] = Header(None, alias="X-Signing-Algo"),
    x_client_pub_key: Optional[str] = Header(None, alias="X-Client-Pub-Key"),
    x_model_pub_key: Optional[str] = Header(None, alias="X-Model-Pub-Key"),
    x_e2ee_version: Optional[str] = Header(None, alias="X-E2EE-Version"),
    x_e2ee_nonce: Optional[str] = Header(None, alias="X-E2EE-Nonce"),
    x_e2ee_timestamp: Optional[str] = Header(None, alias="X-E2EE-Timestamp"),
):
    if not CHUTES_ENABLED:
        return error(status_code=503, message="Chutes route is disabled", type="chutes_disabled")

    if not CHUTES_API_KEY:
        return error(status_code=503, message="CHUTES_API_KEY is not configured", type="chutes_misconfigured")

    return await _chat_completions_impl(
        request=request,
        x_request_hash=x_request_hash,
        x_signing_algo=x_signing_algo,
        x_client_pub_key=x_client_pub_key,
        x_model_pub_key=x_model_pub_key,
        x_e2ee_version=x_e2ee_version,
        x_e2ee_nonce=x_e2ee_nonce,
        x_e2ee_timestamp=x_e2ee_timestamp,
        backend_url=CHUTES_CHAT_COMPLETIONS_URL,
        outbound_headers=_chutes_auth_headers(),
    )


# VLLM completions
@router.post("/completions", dependencies=[Depends(verify_authorization_header)])
async def completions(
    request: Request,
    x_request_hash: Optional[str] = Header(None, alias="X-Request-Hash"),
    x_signing_algo: Optional[str] = Header(None, alias="X-Signing-Algo"),
    x_client_pub_key: Optional[str] = Header(None, alias="X-Client-Pub-Key"),
    x_model_pub_key: Optional[str] = Header(None, alias="X-Model-Pub-Key"),
    x_e2ee_version: Optional[str] = Header(None, alias="X-E2EE-Version"),
    x_e2ee_nonce: Optional[str] = Header(None, alias="X-E2EE-Nonce"),
    x_e2ee_timestamp: Optional[str] = Header(None, alias="X-E2EE-Timestamp"),
):
    # Keep original request body to calculate the request hash for attestation
    request_body = await request.body()
    request_json = json.loads(request_body)

    # E2EE is currently supported only for /chat/completions
    if any([
        x_signing_algo,
        x_client_pub_key,
        x_model_pub_key,
        x_e2ee_version,
        x_e2ee_nonce,
        x_e2ee_timestamp,
    ]):
        return error(
            status_code=400,
            message="E2EE is only supported on /v1/chat/completions",
            type="invalid_e2ee_request",
        )

    modified_json = strip_empty_tool_calls(request_json)

    # Check if the request is for streaming or non-streaming
    is_stream = modified_json.get(
        "stream", False
    )  # Default to non-streaming if not specified
    request_model = modified_json.get("model")
    modified_request_body = json.dumps(modified_json).encode("utf-8")
    if is_stream:
        # Create a streaming response
        return await stream_vllm_response(
            VLLM_COMPLETIONS_URL,
            request_body,
            modified_request_body,
            x_request_hash,
            model_name=request_model,
        )
    else:
        # Handle non-streaming response
        response_data = await non_stream_vllm_response(
            VLLM_COMPLETIONS_URL,
            request_body,
            modified_request_body,
            x_request_hash,
            model_name=request_model,
        )
        return JSONResponse(content=response_data)


# Get signature for chat_id of chat history
@router.get("/signature/{chat_id}", dependencies=[Depends(verify_authorization_header)])
async def signature(request: Request, chat_id: str, signing_algo: str = None, model: Optional[str] = None):
    cache_value = cache.get_chat(chat_id, model_name=model)
    if cache_value is None:
        return not_found("Chat id not found or expired")

    signature = None
    signing_algo = ECDSA if signing_algo is None else signing_algo

    # Retrieve the cached request and response
    try:
        value = json.loads(cache_value)
    except Exception as e:
        log.error(f"Failed to parse the cache value: {cache_value} {e}")
        return unexpect_error("Failed to parse the cache value", e)

    signing_address = None
    if signing_algo == ECDSA:
        signature = value.get("signature_ecdsa")
        signing_address = value.get("signing_address_ecdsa")
    elif signing_algo == ED25519:
        signature = value.get("signature_ed25519")
        signing_address = value.get("signing_address_ed25519")
    else:
        return invalid_signing_algo()

    return dict(
        text=value.get("text"),
        signature=signature,
        signing_address=signing_address,
        signing_algo=signing_algo,
    )


# Metrics of vLLM instance
@router.get("/metrics")
async def metrics(request: Request):
    # Get local metrics from the proxy
    local_metrics = get_proxy_metrics()

    # Fetch metrics from the vLLM backend
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(TIMEOUT)) as client:
            response = await client.get(VLLM_METRICS_URL)
            if response.status_code == 200:
                remote_metrics = response.text
            else:
                log.warning(f"Failed to fetch vLLM metrics: {response.status_code}")
                remote_metrics = f"# Failed to fetch vLLM metrics: {response.status_code}"
    except Exception as e:
        log.error(f"Error fetching vLLM metrics: {e}")
        remote_metrics = f"# Error fetching vLLM metrics: {e}"

    # Combine both and return
    combined_metrics = f"{local_metrics}\n\n# --- vLLM Backend Metrics ---\n\n{remote_metrics}"
    return PlainTextResponse(combined_metrics)


@router.get("/models")
async def models(request: Request):
    async with httpx.AsyncClient(timeout=httpx.Timeout(TIMEOUT)) as client:
        response = await client.get(VLLM_MODELS_URL)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)
        return JSONResponse(content=response.json())


@router.get("/chutes/models", dependencies=[Depends(verify_authorization_header)])
async def chutes_models(request: Request):
    if not CHUTES_ENABLED:
        return error(status_code=503, message="Chutes route is disabled", type="chutes_disabled")

    if not CHUTES_API_KEY:
        return error(status_code=503, message="CHUTES_API_KEY is not configured", type="chutes_misconfigured")

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(TIMEOUT),
        headers=_with_outbound_headers(_chutes_auth_headers()),
    ) as client:
        response = await client.get(CHUTES_MODELS_URL)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)
        return JSONResponse(content=response.json())
