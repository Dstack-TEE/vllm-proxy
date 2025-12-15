import os
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .api import router as api_router
from .api.response.response import ok, error, http_exception
from .logger import log
from .traffic_control import TrafficControl, TrafficControlMiddleware


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    traffic_control: TrafficControl | None = getattr(app.state, "traffic_control", None)
    owns_traffic_control = traffic_control is None
    if owns_traffic_control:
        vllm_base_url = os.getenv("VLLM_BASE_URL", "http://vllm:8000")
        traffic_control = TrafficControl(vllm_base_url)
        app.state.traffic_control = traffic_control
        await traffic_control.start()
    assert traffic_control is not None
    try:
        yield
    finally:
        if owns_traffic_control:
            await traffic_control.stop()


app = FastAPI(lifespan=_lifespan)
app.add_middleware(TrafficControlMiddleware)
app.include_router(api_router)


@app.get("/")
async def root() -> dict:
    return ok()


# Custom global error handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handle all uncaught exceptions globally.
    """
    # handle HTTPException
    if isinstance(exc, HTTPException):
        log.error(f"HTTPException: {exc.detail}")
        return http_exception(exc.status_code, exc.detail)

    log.error(f"Unhandled exception: {exc}")
    return error(
        status_code=500,
        message=str(exc),
        type=type(exc).__name__,
        param=None,
        code=None,
    )
