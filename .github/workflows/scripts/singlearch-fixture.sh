#!/usr/bin/env bash

# Build a fresh fixture for each job; only the disposable loopback registries receive pushes.
set -euo pipefail

registry_image='docker.io/library/registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373'
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../../.." && pwd)"

record_env() {
    printf '%s=%s\n' "$1" "$2" >> "${GITHUB_ENV:?set GITHUB_ENV to the job environment file}"
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
        image="${address}/copa-openssl:test-debian12"
        record_env COPA_TEST_OPENSSL_TAG "$image"
        docker --host "$host" buildx build --builder default --platform linux/amd64 --no-cache \
            --provenance=false --sbom=false --load --tag "$image" \
            --metadata-file "${fixture_dir}/build.json" \
            "${repo_root}/integration/singlearch/fixtures/openssl-test-img-debian"
        docker --host "$host" push "$image"
        curl --max-time 10 -fsS -H 'Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
            "http://${address}/v2/copa-openssl/manifests/test-debian12" > "${fixture_dir}/manifest.json"
        jq -e '.schemaVersion == 2 and has("layers") and (has("manifests") | not)' "${fixture_dir}/manifest.json"
        digest="sha256:$(sha256sum "${fixture_dir}/manifest.json" | cut -d ' ' -f 1)"
        # Preserve registry bytes across Docker versions; save/load can rewrite
        # the manifest even when the image filesystem is unchanged.
        mkdir "${fixture_dir}/registry"
        docker --host "$host" cp "${registry_name}:/var/lib/registry/." "${fixture_dir}/registry"
        record_env COPA_TEST_OPENSSL_IMAGE "${image}@${digest}"
        ;;
    load)
        : "${COPA_TEST_OPENSSL_IMAGE:?run the build step first}"
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
            expected="${COPA_TEST_OPENSSL_IMAGE##*@}"
            actual="sha256:$(timeout 10s docker exec "$COPA_TEST_OPENSSL_REGISTRY" wget -T 5 -q -O - \
                --header='Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
                "http://127.0.0.1:5000/v2/copa-openssl/manifests/${expected}" | sha256sum | cut -d ' ' -f 1)"
            if [[ "$actual" != "$expected" ]]; then
                echo "Mirrored fixture digest mismatch: expected ${expected}, got ${actual}" >&2
                exit 1
            fi
            echo "Mirrored fixture manifest ${actual}"
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
            if [[ -n "${COPA_TEST_OPENSSL_TAG:-}" ]]; then
                timeout 30s docker --host "$host" image rm "$COPA_TEST_OPENSSL_TAG" || true
            fi
            rm -rf -- "$COPA_TEST_OPENSSL_DIR"
        fi
        ;;
    *)
        echo "usage: $0 build|load|cleanup" >&2
        exit 2
        ;;
esac
