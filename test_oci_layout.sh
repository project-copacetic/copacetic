#!/bin/bash

# Simple test for Copa OCI Layout functionality
set -e

# Configuration
IMAGE="nginx:1.27.0"
PLATFORMS="linux/amd64,linux/arm64"
OCI_DIR="/tmp/copa-oci-test-$(date +%s)"

# Clean up any existing directory
if [ -d "$OCI_DIR" ]; then
    echo "🧹 Cleaning up existing OCI directory: $OCI_DIR"
    rm -rf "$OCI_DIR"
fi

# Test copa patch with --oci-dir (no report)
echo "🚀 Running Copa with OCI layout output..."
echo "Command: ./dist/darwin_arm64/release/copa patch --image $IMAGE --oci-dir $OCI_DIR --platforms=linux/amd64,linux/arm64 --debug"
echo ""

./dist/darwin_arm64/release/copa patch \
    --image "$IMAGE" \
    --platform linux/arm64,linux/amd64 \
    --oci-dir "$OCI_DIR" \
    --debug

# Check if OCI layout was created
echo ""
echo "Checking OCI layout creation..."
if [ -d "$OCI_DIR" ]; then
    echo "✅ OCI layout directory created at: $OCI_DIR"
    echo "Contents:"
    ls -la "$OCI_DIR"
    
    # Check for common OCI layout files
    if [ -f "$OCI_DIR/oci-layout" ]; then
        echo "✅ oci-layout file found"
    fi
    
    if [ -f "$OCI_DIR/index.json" ]; then
        echo "✅ index.json found"
        echo "Index content:"
        cat "$OCI_DIR/index.json"
    fi
    
    if [ -d "$OCI_DIR/blobs" ]; then
        echo "✅ blobs directory found"
        echo "Blob count: $(find "$OCI_DIR/blobs" -type f | wc -l)"
    fi
else
    echo "❌ OCI layout directory was not created"
    exit 1
fi
