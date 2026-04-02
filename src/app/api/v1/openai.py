import base64
import json
import os
import time
from hashlib import sha256
from typing import Any, Optional

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
CHUTES_ATTESTATION_BASE_URL = os.getenv("CHUTES_ATTESTATION_BASE_URL", "https://api.chutes.ai").rstrip("/")
CHUTES_CHAT_COMPLETIONS_URL = f"{CHUTES_BASE_URL}/v1/chat/completions"
CHUTES_MODELS_URL = f"{CHUTES_BASE_URL}/v1/models"
CHUTES_API_KEY = os.getenv("CHUTES_API_KEY")
CHUTES_CHUTE_ID_CACHE: dict[str, tuple[str, float]] = {}
CHUTES_CHUTE_ID_CACHE_TTL_SECONDS = int(os.getenv("CHUTES_CHUTE_ID_CACHE_TTL_SECONDS", "3600"))

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


def _error_from_upstream_429(response: httpx.Response):
    retry_after = response.headers.get("Retry-After")
    msg = "Upstream attestation is rate limited"
    if retry_after:
        msg = f"{msg}; retry after {retry_after} seconds"
    return error(status_code=429, message=msg, type="upstream_rate_limited")


async def _resolve_chute_id(client: httpx.AsyncClient, model: str) -> str | dict:
    now = time.time()
    cached = CHUTES_CHUTE_ID_CACHE.get(model)
    if cached and now - cached[1] < CHUTES_CHUTE_ID_CACHE_TTL_SECONDS:
        return cached[0]

    resp = await client.get(
        f"{CHUTES_ATTESTATION_BASE_URL}/chutes/",
        params={"include_public": "true", "name": model},
    )
    if resp.status_code == 429:
        return _error_from_upstream_429(resp)
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)

    data = resp.json()
    items = data.get("items") or []
    if not items:
        return error(status_code=404, message=f"No chute found for model: {model}", type="upstream_model_not_found")

    chute_id = items[0].get("chute_id")
    if not chute_id:
        return error(status_code=502, message="Upstream chute lookup missing chute_id", type="upstream_invalid_response")

    CHUTES_CHUTE_ID_CACHE[model] = (chute_id, now)
    return chute_id


async def _fetch_chutes_attestation(client: httpx.AsyncClient, model: str, nonce: str) -> tuple[dict | None, dict | None]:
    chute_id_or_error = await _resolve_chute_id(client, model)
    if isinstance(chute_id_or_error, dict) and chute_id_or_error.get("error"):
        return None, chute_id_or_error
    chute_id = chute_id_or_error

    e2e_resp = await client.get(f"{CHUTES_ATTESTATION_BASE_URL}/e2e/instances/{chute_id}")
    if e2e_resp.status_code == 429:
        return None, _error_from_upstream_429(e2e_resp)
    if e2e_resp.status_code != 200:
        raise HTTPException(status_code=e2e_resp.status_code, detail=e2e_resp.text)

    e2e_data = e2e_resp.json()
    instances = e2e_data.get("instances") or []
    pubkeys = {i.get("instance_id"): i.get("e2e_pubkey") for i in instances if i.get("instance_id")}

    evidence_resp = await client.get(
        f"{CHUTES_ATTESTATION_BASE_URL}/chutes/{chute_id}/evidence",
        params={"nonce": nonce},
    )
    if evidence_resp.status_code == 429:
        return None, _error_from_upstream_429(evidence_resp)
    if evidence_resp.status_code != 200:
        raise HTTPException(status_code=evidence_resp.status_code, detail=evidence_resp.text)

    evidence_data = evidence_resp.json()
    evidence_list = evidence_data.get("evidence") or []

    all_attestations = []
    for e in evidence_list:
        iid = e.get("instance_id")
        e2e_pubkey = pubkeys.get(iid)
        if not iid or not e2e_pubkey:
            continue
        all_attestations.append(
            {
                "instance_id": iid,
                "nonce": nonce,
                "e2e_pubkey": e2e_pubkey,
                "intel_quote": e.get("quote"),
                "gpu_evidence": e.get("gpu_evidence", []),
                "gpu_tokens": e.get("gpu_tokens"),
                "tdx_verification": e.get("tdx_verification"),
                "certificate": e.get("certificate"),
            }
        )

    if not all_attestations:
        return None, error(status_code=502, message="No usable upstream attestations returned", type="upstream_invalid_response")

    return {
        "attestation_type": "chutes",
        "nonce": nonce,
        "chute_id": chute_id,
        "all_attestations": all_attestations,
    }, None


def _decode_quote(quote_b64: str) -> bytes:
    return base64.b64decode(quote_b64)


def _extract_td_attributes(quote_bytes: bytes) -> int:
    body = quote_bytes[48 : 48 + 584]
    td_attributes_hex = body[120:128].hex()
    return int(td_attributes_hex, 16)


def _extract_report_data_sha256(quote_bytes: bytes) -> str:
    td_report_bytes = quote_bytes[48:632]
    report_data_hex = td_report_bytes[520:584].hex().lower()
    return report_data_hex[:64]


def _decode_jwt_payload_without_verification(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("invalid_jwt_format")
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    decoded = base64.urlsafe_b64decode(payload.encode("utf-8")).decode("utf-8")
    return json.loads(decoded)


def _extract_gpu_tokens(attestation: dict[str, Any]) -> Any:
    if "gpu_tokens" in attestation:
        return attestation.get("gpu_tokens")
    return attestation.get("gpu_evidence")


def _verify_single_chutes_attestation(attestation: dict[str, Any], nonce: str) -> list[str]:
    errors: list[str] = []

    quote_b64 = attestation.get("intel_quote") or attestation.get("quote")
    e2e_pubkey = attestation.get("e2e_pubkey")
    if not quote_b64:
        return ["missing_intel_quote"]
    if not e2e_pubkey:
        return ["missing_e2e_pubkey"]

    try:
        quote_bytes = _decode_quote(quote_b64)
    except Exception:
        return ["invalid_quote_base64"]

    tdx_result = (attestation.get("tdx_verification") or {}).get("result") or {}
    tdx_status = tdx_result.get("status")
    if tdx_status != "UpToDate":
        errors.append(f"tdx_status_not_uptodate:{tdx_status or 'missing'}")

    try:
        td_attributes = _extract_td_attributes(quote_bytes)
        if td_attributes & 1:
            errors.append("tdx_debug_mode_enabled")
    except Exception:
        errors.append("tdx_attributes_parse_failed")

    expected_report_data = sha256((nonce + e2e_pubkey).encode("utf-8")).hexdigest().lower()
    actual_report_data = _extract_report_data_sha256(quote_bytes)
    if actual_report_data != expected_report_data:
        errors.append("report_data_binding_mismatch")

    gpu_tokens = _extract_gpu_tokens(attestation)
    if isinstance(gpu_tokens, dict):
        if gpu_tokens.get("error"):
            errors.append("gpu_tokens_error")
        tokens = gpu_tokens.get("tokens")
        if tokens:
            try:
                platform_entry = tokens[0]
                if not isinstance(platform_entry, list) or len(platform_entry) < 2:
                    errors.append("gpu_platform_token_format_invalid")
                else:
                    platform_claims = _decode_jwt_payload_without_verification(platform_entry[1])
                    if platform_claims.get("x-nvidia-overall-att-result") is not True:
                        errors.append("gpu_overall_attestation_failed")
                    if platform_claims.get("eat_nonce") != expected_report_data:
                        errors.append("gpu_eat_nonce_mismatch")
            except Exception:
                errors.append("gpu_tokens_parse_failed")

    return errors


def _verify_chutes_attestation_bundle(attestation_bundle: dict[str, Any], nonce: str) -> tuple[bool, list[dict[str, Any]]]:
    details: list[dict[str, Any]] = []
    attestations = attestation_bundle.get("all_attestations") or []
    if not attestations:
        return False, [{"instance_id": None, "errors": ["missing_all_attestations"]}]

    all_ok = True
    for att in attestations:
        instance_id = att.get("instance_id")
        att_errors = _verify_single_chutes_attestation(att, nonce)
        if att_errors:
            all_ok = False
        details.append({"instance_id": instance_id, "errors": att_errors})

    return all_ok, details


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
    verify_mode: str = Query("proxy"),
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
    mode = verify_mode.strip().lower()
    if mode not in {"proxy", "passthrough"}:
        return error(status_code=400, message="verify_mode must be one of: proxy, passthrough", type="invalid_verify_mode")

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

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(TIMEOUT),
            headers={"Authorization": f"Bearer {CHUTES_API_KEY}"},
        ) as client:
            upstream_attestation, upstream_error = await _fetch_chutes_attestation(client, model, nonce)
    except httpx.RequestError as exc:
        return error(status_code=502, message=f"Failed to fetch upstream attestation: {exc}", type="upstream_unreachable")

    if upstream_error is not None:
        return upstream_error

    upstream_raw = json.dumps(upstream_attestation, sort_keys=True, separators=(",", ":"))
    upstream_attestation_sha256 = sha256(upstream_raw.encode("utf-8")).hexdigest()

    context = ecdsa_context if algo == ECDSA else ed25519_context

    binding_payload = {
        "nonce": nonce,
        "timestamp": int(time.time()),
        "provider": "chutes",
        "upstream_base_url": CHUTES_ATTESTATION_BASE_URL,
        "model": model,
        "upstream_attestation_sha256": upstream_attestation_sha256,
    }
    binding_text = json.dumps(binding_payload, sort_keys=True, separators=(",", ":"))
    binding_proof = {
        "payload": binding_payload,
        "signature": sign_message(context, binding_text),
        "signing_algo": algo,
        "signing_address": context.signing_address,
    }

    if mode == "passthrough":
        return {
            "version": "1",
            "verify_mode": mode,
            "proxy": {
                "attestation": proxy_attestation,
                "signing_public_key": proxy_attestation.get("signing_public_key"),
            },
            "upstream": {
                "provider": "chutes",
                "base_url": CHUTES_ATTESTATION_BASE_URL,
                "model": model,
                "attestation": upstream_attestation,
                "attestation_sha256": upstream_attestation_sha256,
            },
            "binding_proof": binding_proof,
        }

    verified, verification_details = _verify_chutes_attestation_bundle(upstream_attestation, nonce)
    if not verified:
        return error(
            status_code=502,
            message=f"Chutes attestation verification failed in proxy mode: {json.dumps(verification_details, separators=(',', ':'))}",
            type="chutes_verification_failed",
        )

    receipt_payload = {
        "nonce": nonce,
        "request_hash": sha256(f"{model}:{nonce}".encode("utf-8")).hexdigest(),
        "provider": "chutes",
        "model": model,
        "verify_mode": mode,
        "verification_policy": "chutes-v1",
        "verification_policy_version": "1",
        "upstream_attestation_sha256": upstream_attestation_sha256,
        "binding_signature": binding_proof["signature"],
        "binding_signing_algo": binding_proof["signing_algo"],
        "binding_signing_address": binding_proof["signing_address"],
        "verified_at": int(time.time()),
        "result": "pass",
    }
    receipt_text = json.dumps(receipt_payload, sort_keys=True, separators=(",", ":"))

    return {
        "version": "1",
        "verify_mode": mode,
        "proxy": {
            "attestation": proxy_attestation,
            "signing_public_key": proxy_attestation.get("signing_public_key"),
        },
        "verification_receipt": {
            "payload": receipt_payload,
            "signature": sign_message(context, receipt_text),
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
