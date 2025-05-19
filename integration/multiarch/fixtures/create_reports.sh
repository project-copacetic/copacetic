#!/usr/bin/env bash
# scan-matrix.sh – tiny CLI wrapper around Trivy for multi-arch scans
set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") -i <image[:tag]> [-p <platforms>] [-o <report_dir>]

  -i  Container image (with optional tag or digest) to scan.               (required)
  -p  Comma-separated platform list (default: all common Linux arches).   (optional)
        e.g. "linux/amd64,linux/arm64,linux/ppc64le"
  -o  Output directory for JSON reports (default: /tmp/reports).          (optional)
  -h  Show this help.

The script spawns one Trivy scan per platform and drops JSON results into
<report_dir>/report-<os>-<arch>.json
EOF
  exit "${1:-0}"
}

# ---------- defaults ----------
PLATFORMS='linux/amd64,linux/arm/v5,linux/arm64,linux/386,linux/mips64le,linux/ppc64le,linux/s390x'
REPORT_DIR='/tmp/reports'
IMAGE=''

# ---------- arg parsing ----------
while getopts ':i:p:o:h' flag; do
  case "$flag" in
    i) IMAGE="$OPTARG" ;;
    p) PLATFORMS="$OPTARG" ;;
    o) REPORT_DIR="$OPTARG" ;;
    h) usage 0 ;;
    *) usage 1 ;;
  esac
done

[[ -z "$IMAGE" ]] && { echo "❌  -i <image> is required"; usage 1; }

# ---------- prep ----------
rm -rf "$REPORT_DIR"
mkdir -p "$REPORT_DIR"
IFS=',' read -ra PLATFORM_ARR <<<"$PLATFORMS"

# ---------- scan loop ----------
for platform in "${PLATFORM_ARR[@]}"; do
  suffix=${platform//\//-}           # linux/amd64 → linux-amd64
  out="${REPORT_DIR}/report-${suffix}.json"

  echo "▶️  Scanning $IMAGE for $platform …"
  trivy image \
    --platform "$platform" \
    --image-src remote \
    --pkg-types os \
    --ignore-unfixed \
    --format json \
    -o "$out" \
    "$IMAGE"
done

echo "✅  Reports saved under $REPORT_DIR"
