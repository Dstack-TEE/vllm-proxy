from fastapi import FastAPI, HTTPException, Request

from .api import router as api_router
from .api.response.response import ok, error, http_exception
from .logger import log
from .metrics import vllm_proxy_errors_total
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI()
app.include_router(api_router)

# Initialize Prometheus Instrumentator
Instrumentator().instrument(app).expose(app, endpoint="/local-metrics", include_in_schema=False)


@app.get("/")
async def root():
    return ok()


# Custom global error handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Handle all uncaught exceptions globally.
    """
    # handle HTTPException
    if isinstance(exc, HTTPException):
        log.error(f"HTTPException: {exc.detail}")
        return http_exception(exc.status_code, exc.detail)

    log.error(f"Unhandled exception: {exc}")
    vllm_proxy_errors_total.labels(type=type(exc).__name__).inc()
    return error(
        status_code=500,
        message=str(exc),
        type=type(exc).__name__,
        param=None,
        code=None,
    )
