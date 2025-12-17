#!/bin/bash

set -euo pipefail

# Default image name
IMAGE=${1:-vllm-proxy:latest}
TARGET=${2:-runtime}

echo "Image: $IMAGE"
echo "Target: $TARGET"

# Build the Docker image with the specified version
docker build \
    --no-cache \
    -f docker/Dockerfile \
    --target "$TARGET" \
    -t "$IMAGE" \
    .
