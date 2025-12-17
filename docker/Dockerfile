# syntax=docker/dockerfile:1.7

# The proxy talks to a separate vLLM server; it doesn't need the multi-GB vLLM runtime image.
# Keep the image small by using a slim Python base + venv, and rely on the NVIDIA runtime to
# mount driver libraries (e.g., NVML) when GPU features are enabled.
FROM python:3.12-slim-bookworm AS builder

ARG UV_VERSION=0.9.17

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_NO_MANAGED_PYTHON=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir "uv==${UV_VERSION}"

ENV VIRTUAL_ENV=/opt/venv
RUN python -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /tmp
COPY requirements.txt ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --strict -r requirements.txt

FROM builder AS gpu-builder

ENV VIRTUAL_ENV=/opt/ppcie-venv
RUN python -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /tmp
COPY requirements-gpu.txt ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --strict -r requirements-gpu.txt

FROM python:3.12-slim-bookworm AS runtime

ENV VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY src ./

EXPOSE 8000
ENTRYPOINT ["./entrypoint.sh"]

FROM runtime AS runtime-gpu
COPY --from=gpu-builder /opt/ppcie-venv /opt/ppcie-venv
ENV GPU_EVIDENCE_PYTHON=/opt/ppcie-venv/bin/python
ENV NVIDIA_VISIBLE_DEVICES=all
ENV NVIDIA_DRIVER_CAPABILITIES=compute,utility
