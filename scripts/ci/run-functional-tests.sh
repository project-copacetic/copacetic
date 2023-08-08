#!/usr/bin/env bash

set -eu -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

: "${TEST_BUILDKIT_MODE:="direct/tcp"}"
: "${COPA:=copa}"
: "${COPA_FLAGS:=}"

IMAGE_NAMED_TAGGED="${IMAGE_REF%@*}"
IMAGE_TAG_ONLY="${IMAGE_NAMED_TAGGED#*:}"
IMAGE_NAME_ONLY="${IMAGE_NAMED_TAGGED%:*}"
: "${IMAGE_TAG_PATCHED:="${IMAGE_TAG_ONLY}-patched"}"

echo "[INFO]: Buildkit mode: ${TEST_BUILDKIT_MODE}"
echo "[INFO]: Image to patch: ${IMAGE_REF}"
echo "[INFO]: Patched image tag: ${IMAGE_TAG_PATCHED}"

echo "[INFO]: Scanning image with trivy ..."
trivy image --vuln-type os --ignore-unfixed --scanners vuln -f json -o scan.json "${IMAGE_REF}" --exit-on-eol 1 --ignore-policy "${SCRIPT_DIR}/trivy_ignore.rego"
echo "[INFO]: Setting up buildkit with mode ${TEST_BUILDKIT_MODE} ..."

if [ ! -f "${SCRIPT_DIR}/setup/${TEST_BUILDKIT_MODE}" ]; then
    echo "[ERROR]: Unknown mode: ${TEST_BUILDKIT_MODE}" >&2
    exit 1
fi

. "${SCRIPT_DIR}/setup/${TEST_BUILDKIT_MODE}"

echo "[INFO]: Run copa on target ..."
if [ -v COPA_BUILDKIT_ADDR ] && [ -n "${COPA_BUILDKIT_ADDR}" ]; then
    COPA_FLAGS+="-a ${COPA_BUILDKIT_ADDR}"
fi
"${COPA}" patch -i "${IMAGE_REF}" -r scan.json -t "${IMAGE_TAG_PATCHED}" --timeout 20m ${COPA_FLAGS}

echo "[INFO]: Rescanning patched image with same vuln DB ..."
trivy image --vuln-type os --ignore-unfixed --skip-db-update --scanners vuln "${IMAGE_NAME_ONLY}:${IMAGE_TAG_PATCHED}" --exit-code 1 --exit-on-eol 1 --ignore-policy "${SCRIPT_DIR}/trivy_ignore.rego"
