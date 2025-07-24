#!/bin/bash

set -e

# Build the Copa frontend image
IMAGE_NAME=${1:-copa-frontend:latest}

echo "Building Copa frontend image: $IMAGE_NAME"

# Build the frontend container image
docker build -f frontend.Dockerfile -t "$IMAGE_NAME" .

echo "Copa frontend image built successfully: $IMAGE_NAME"

# Usage instructions
echo ""
echo "Usage with BuildKit:"
echo "  buildctl build \\"
echo "    --frontend=gateway.v0 \\"
echo "    --opt source=$IMAGE_NAME \\"
echo "    --opt image=ubuntu:20.04 \\"
echo "    --opt report='{\"metadata\":{\"os\":{\"type\":\"ubuntu\",\"version\":\"20.04\"},\"config\":{\"arch\":\"amd64\"}},\"updates\":[{\"name\":\"curl\",\"installedVersion\":\"7.68.0-1\",\"fixedVersion\":\"7.68.0-2\",\"vulnerabilityID\":\"CVE-2023-1234\"}]}' \\"
echo "    --output type=docker,dest=patched.tar"