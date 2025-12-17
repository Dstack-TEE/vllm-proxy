import asyncio
import os
import time
from collections.abc import Callable
from typing import Optional

import httpx
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.logger import log


def _parse_num_requests_waiting(metrics_text: str) -> float:
    max_waiting = 0.0
    for line in metrics_text.splitlines():
        if not line.startswith("vllm:num_requests_waiting"):
            continue
        try:
            value = float(line.split()[-1])
        except (IndexError, ValueError):
            continue
        if value > max_waiting:
            max_waiting = value
    return max_waiting


def _normalize_user_tier(raw: Optional[str]) -> str:
    if raw and raw.strip().lower() == "premium":
        return "premium"
    return "basic"


def _basic_max_request() -> int:
    raw = os.getenv("BASIC_MAX_REQUEST", "20").strip()
    try:
        value = int(raw)
    except ValueError:
        value = 20
    return max(1, value)


def _metrics_timeout_seconds() -> float:
    raw = os.getenv("METRICS_TIMEOUT_SECONDS", "2").strip()
    try:
        return float(raw)
    except ValueError:
        return 2.0


def _metrics_poll_interval_seconds() -> float:
    raw = os.getenv("METRICS_POLL_INTERVAL_SECONDS", "2").strip()
    try:
        value = float(raw)
    except ValueError:
        value = 2.0
    return max(0.5, min(10.0, value))


def _metrics_max_age_seconds() -> float:
    raw = os.getenv("METRICS_MAX_AGE_SECONDS", "30").strip()
    try:
        value = float(raw)
    except ValueError:
        value = 30.0
    return max(10.0, min(30.0, value))


class TrafficControl:
    def __init__(self, vllm_base_url: str) -> None:
        base = vllm_base_url.rstrip("/")
        self._metrics_url = f"{base}/metrics"

        self._busy = False
        self._last_ok_monotonic: Optional[float] = None
        self._in_flight = 0

        self._task: Optional[asyncio.Task[None]] = None
        self._stop = asyncio.Event()

    def _update_from_metrics(self, metrics_text: str) -> None:
        waiting = _parse_num_requests_waiting(metrics_text)
        now = time.monotonic()
        self._busy = waiting > 0
        self._last_ok_monotonic = now

    def _backend_busy_or_stale(self) -> bool:
        last_ok = self._last_ok_monotonic
        if last_ok is None or (time.monotonic() - last_ok) > _metrics_max_age_seconds():
            return False
        return self._busy

    def start_inference(self, user_tier_header: Optional[str]) -> Callable[[], None]:
        tier = _normalize_user_tier(user_tier_header)
        if tier != "premium":
            if self._backend_busy_or_stale():
                raise HTTPException(status_code=429, detail="Upstream vLLM is congested")
            limit = _basic_max_request()
            if self._in_flight >= limit:
                raise HTTPException(status_code=429, detail="Too many concurrent requests")
        self._in_flight += 1

        finished = False

        def finish() -> None:
            nonlocal finished
            if finished:
                return
            finished = True
            self._in_flight = max(0, self._in_flight - 1)

        return finish

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        except Exception:
            pass
        self._task = None

    async def refresh_once(self) -> None:
        timeout = httpx.Timeout(_metrics_timeout_seconds())
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                resp = await client.get(self._metrics_url)
            except Exception:
                return
            if resp.status_code != 200:
                return
            try:
                self._update_from_metrics(resp.text)
            except Exception:
                return

    async def _run(self) -> None:
        interval = _metrics_poll_interval_seconds()
        while not self._stop.is_set():
            try:
                await self.refresh_once()
            except Exception as exc:
                log.debug(f"metrics refresh failed: {exc}")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass


def _get_header(scope: Scope, name: bytes) -> Optional[bytes]:
    for k, v in scope.get("headers", ()):
        if k == name or k.lower() == name:
            return v
    return None


def _authorized(scope: Scope) -> bool:
    auth = _get_header(scope, b"authorization")
    if not auth:
        return False
    try:
        auth_str = auth.decode("latin-1")
    except Exception:
        return False
    if not auth_str.startswith("Bearer "):
        return False
    token = auth_str.split("Bearer ", 1)[1]
    return token == os.getenv("TOKEN")


class TrafficControlMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path") or ""
        method = scope.get("method") or ""
        if method != "POST" or path not in ("/v1/chat/completions", "/v1/completions"):
            await self.app(scope, receive, send)
            return

        if not _authorized(scope):
            await self.app(scope, receive, send)
            return

        app_obj = scope.get("app")
        traffic_control: Optional[TrafficControl] = None
        if app_obj is not None and hasattr(app_obj, "state"):
            traffic_control = getattr(app_obj.state, "traffic_control", None)
        if traffic_control is None:
            await self.app(scope, receive, send)
            return

        tier = _get_header(scope, b"x-user-tier")
        tier_str = tier.decode("latin-1") if tier else None
        try:
            finish = traffic_control.start_inference(tier_str)
        except HTTPException as exc:
            response = JSONResponse(
                status_code=exc.status_code,
                content={"error": {"message": str(exc.detail), "type": "rate_limit"}},
            )
            await response(scope, receive, send)
            return

        finished = False

        async def send_wrapper(message: Message) -> None:
            nonlocal finished
            await send(message)
            if message.get("type") == "http.response.body" and not message.get("more_body", False):
                if not finished:
                    finished = True
                    finish()

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            if not finished:
                finish()
