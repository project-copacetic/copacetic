#!/usr/bin/env bash

# Build a fresh fixture for each job; only the disposable loopback registries receive pushes.
set -euo pipefail

registry_image='docker.io/library/registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373'
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../../.." && pwd)"

record_env() {
    printf '%s=%s\n' "$1" "$2" >> "${GITHUB_ENV:?set GITHUB_ENV to the job environment file}"
}

manifest_accept='Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'

# build_fixture DIR ADDRESS NAME TAG ENV_IMAGE CONTEXT [BUILD-ARGS...]
# Builds a linux/amd64 image with the daemon at $host, pushes it to the loopback
# registry at ADDRESS and records the pushed manifest's digest in ENV_IMAGE. The
# tag is recorded first, in ENV_IMAGE with _IMAGE replaced by _TAG, so cleanup
# can remove a partial build.
build_fixture() {
    local fixture_dir="$1" address="$2" name="$3" tag="$4" env_name="$5" context="$6"
    shift 6
    local image="${address}/${name}:${tag}" files="${fixture_dir}/${name}-${tag}"
    record_env "${env_name%_IMAGE}_TAG" "$image"
    docker --host "$host" buildx build --builder default --platform linux/amd64 --no-cache \
        --provenance=false --sbom=false --load --tag "$image" \
        --metadata-file "${files}-build.json" "$@" "$context"
    docker --host "$host" push "$image"
    curl --max-time 10 -fsS -H "$manifest_accept" \
        "http://${address}/v2/${name}/manifests/${tag}" > "${files}-manifest.json"
    jq -e '.schemaVersion == 2 and has("layers") and (has("manifests") | not)' "${files}-manifest.json"
    local digest
    digest="sha256:$(sha256sum "${files}-manifest.json" | cut -d ' ' -f 1)"
    record_env "$env_name" "${image}@${digest}"
}

# AlmaLinux fixtures with their repositories switched from the geo mirrorlist
# to repo.almalinux.org, one "ENV BASE-IMAGE TAG" per line. The gateway tests
# use the floating almalinux:9 tag, which must match almaLinux9Image's fallback
# in integration/gateway/distro_test.go; the singlearch base is the pinned
# test-images.json entry that names COPA_TEST_ALMALINUX94_IMAGE.
almalinux_fixtures() {
    printf '%s %s %s\n' COPA_TEST_ALMALINUX9_IMAGE docker.io/library/almalinux:9 9
    jq -r '.[] | select(.imageEnv == "COPA_TEST_ALMALINUX94_IMAGE") | "\(.imageEnv) \(.image):\(.tag)@\(.digest) \(.tag)"' \
        "${repo_root}/integration/singlearch/fixtures/test-images.json"
}

case "${1:-}" in
    build)
        fixture_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/copa-openssl.XXXXXX")"
        registry_name="${fixture_dir##*/}"
        host="${DOCKER_HOST:-$(docker context inspect --format '{{.Endpoints.docker.Host}}')}"
        record_env COPA_TEST_OPENSSL_DIR "$fixture_dir"
        record_env COPA_TEST_OPENSSL_REGISTRY "$registry_name"
        record_env COPA_TEST_OPENSSL_DOCKER_HOST "$host"
        record_env COPA_TEST_BUILDX_BUILDER "${registry_name}-buildx"
        record_env DOCKER_DIND_VOLUME "${registry_name}-dind"
        # Select an isolated loopback port for the standalone TCP test daemon.
        if [[ -z "${BUILDKIT_PORT:-}" ]]; then
            buildkit_port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
            record_env BUILDKIT_PORT "$buildkit_port"
        fi
        docker --host "$host" run -d --name "$registry_name" -p 127.0.0.1::5000 "$registry_image"
        address="$(docker --host "$host" port "$registry_name" 5000/tcp)"
        for _ in {1..30}; do
            if curl --max-time 2 -fsS "http://${address}/v2/" >/dev/null; then
                break
            fi
            sleep 1
        done
        curl --max-time 2 -fsS "http://${address}/v2/" >/dev/null
        build_fixture "$fixture_dir" "$address" copa-openssl test-debian12 COPA_TEST_OPENSSL_IMAGE \
            "${repo_root}/integration/singlearch/fixtures/openssl-test-img-debian"
        almalinux="$(almalinux_fixtures)"
        if [[ "$(wc -l <<< "$almalinux")" -ne 2 ]]; then
            echo "Expected 2 AlmaLinux fixtures, found: ${almalinux}" >&2
            exit 1
        fi
        # --pull keeps the floating almalinux:9 base current even when the
        # daemon already holds an older copy of the tag.
        while read -r env_name base tag; do
            build_fixture "$fixture_dir" "$address" copa-almalinux "$tag" "$env_name" \
                "${repo_root}/integration/singlearch/fixtures/almalinux-baseurl" \
                --pull --build-arg "BASE_IMAGE=${base}"
        done <<< "$almalinux"
        # Preserve registry bytes across Docker versions; save/load can rewrite
        # the manifest even when the image filesystem is unchanged.
        mkdir "${fixture_dir}/registry"
        docker --host "$host" cp "${registry_name}:/var/lib/registry/." "${fixture_dir}/registry"
        ;;
    load)
        : "${COPA_TEST_OPENSSL_IMAGE:?run the build step first}"
        : "${COPA_TEST_ALMALINUX9_IMAGE:?run the build step first}"
        : "${COPA_TEST_ALMALINUX94_IMAGE:?run the build step first}"
        if [[ "${DOCKER_HOST:-$COPA_TEST_OPENSSL_DOCKER_HOST}" != "$COPA_TEST_OPENSSL_DOCKER_HOST" ]]; then
            # custom-unix runs a separate dockerd. Its loopback registry needs the same
            # bytes and address; keep that daemon's networking isolated from the host.
            address="${COPA_TEST_OPENSSL_TAG%%/*}"
            docker create --name "$COPA_TEST_OPENSSL_REGISTRY" \
                -p "127.0.0.1:${address##*:}:5000" "$registry_image"
            docker cp "${COPA_TEST_OPENSSL_DIR}/registry/." "${COPA_TEST_OPENSSL_REGISTRY}:/var/lib/registry"
            docker start "$COPA_TEST_OPENSSL_REGISTRY"
            for _ in {1..30}; do
                if timeout 5s docker exec "$COPA_TEST_OPENSSL_REGISTRY" wget -T 2 -q -O /dev/null http://127.0.0.1:5000/v2/; then
                    break
                fi
                sleep 1
            done
            timeout 5s docker exec "$COPA_TEST_OPENSSL_REGISTRY" wget -T 2 -q -O /dev/null http://127.0.0.1:5000/v2/
            for image in "$COPA_TEST_OPENSSL_IMAGE" "$COPA_TEST_ALMALINUX9_IMAGE" "$COPA_TEST_ALMALINUX94_IMAGE"; do
                name="${image#*/}"
                name="${name%%[:@]*}"
                expected="${image##*@}"
                actual="sha256:$(timeout 10s docker exec "$COPA_TEST_OPENSSL_REGISTRY" wget -T 5 -q -O - \
                    --header="$manifest_accept" \
                    "http://127.0.0.1:5000/v2/${name}/manifests/${expected}" | sha256sum | cut -d ' ' -f 1)"
                if [[ "$actual" != "$expected" ]]; then
                    echo "Mirrored fixture ${name} digest mismatch: expected ${expected}, got ${actual}" >&2
                    exit 1
                fi
                echo "Mirrored fixture ${name} manifest ${actual}"
            done
        fi
        ;;
    cleanup)
        if [[ -n "${COPA_TEST_OPENSSL_DOCKER_HOST:-}" ]]; then
            host="$COPA_TEST_OPENSSL_DOCKER_HOST"
            if [[ -n "${DOCKER_CUSTOM_UNIX_ID:-}" ]]; then
                timeout 30s docker --host "$host" rm -f "$DOCKER_CUSTOM_UNIX_ID" || true
                timeout 30s docker --host "$host" volume rm "$DOCKER_DIND_VOLUME" || true
                if [[ -n "${SOCK_DIR:-}" ]]; then
                    sudo rm -rf -- "$SOCK_DIR"
                fi
            fi
            if timeout 10s docker --host "$host" buildx inspect "$COPA_TEST_BUILDX_BUILDER" >/dev/null 2>&1; then
                timeout 30s docker --host "$host" buildx rm "$COPA_TEST_BUILDX_BUILDER" || true
            fi
            timeout 30s docker --host "$host" rm -fv "$COPA_TEST_OPENSSL_REGISTRY" || true
            for tag in "${COPA_TEST_OPENSSL_TAG:-}" "${COPA_TEST_ALMALINUX9_TAG:-}" "${COPA_TEST_ALMALINUX94_TAG:-}"; do
                if [[ -n "$tag" ]]; then
                    timeout 30s docker --host "$host" image rm "$tag" || true
                fi
            done
            rm -rf -- "$COPA_TEST_OPENSSL_DIR"
        fi
        ;;
    *)
        echo "usage: $0 build|load|cleanup" >&2
        exit 2
        ;;
esac
