# syntax=docker/dockerfile:1.7

# Build the project-owned Chisel tooling image locally, tag it, and pass that
# tag with --build-arg CHISEL_TOOL_IMAGE=... . No published Copa tooling-image
# digest is required by this fixture.
ARG CHISEL_TOOL_IMAGE=copa-chisel:local
FROM ${CHISEL_TOOL_IMAGE} AS cutter

ARG TARGETARCH
ARG TARGETVARIANT
ARG CHISEL_RELEASE_REPOSITORY=https://github.com/canonical/chisel-releases.git
ARG CHISEL_RELEASE_COMMIT=ca7ad8113998470ff77231af799c363c4a48feca

RUN set -eu; \
    git init /tmp/chisel-release; \
    git -C /tmp/chisel-release remote add origin "${CHISEL_RELEASE_REPOSITORY}"; \
    git -C /tmp/chisel-release fetch --depth=1 origin "${CHISEL_RELEASE_COMMIT}"; \
    git -C /tmp/chisel-release checkout --detach FETCH_HEAD; \
    test "$(git -C /tmp/chisel-release rev-parse HEAD)" = "${CHISEL_RELEASE_COMMIT}"

RUN set -eu; \
    case "${TARGETARCH}/${TARGETVARIANT}" in \
      amd64/) chisel_arch=amd64 ;; \
      arm64/*) chisel_arch=arm64 ;; \
      386/) chisel_arch=i386 ;; \
      arm/v7) chisel_arch=armhf ;; \
      ppc64le/) chisel_arch=ppc64el ;; \
      s390x/) chisel_arch=s390x ;; \
      riscv64/) chisel_arch=riscv64 ;; \
      *) echo "unsupported fixture platform ${TARGETARCH}/${TARGETVARIANT}" >&2; exit 1 ;; \
    esac; \
    mkdir -p /rootfs; \
    chisel cut \
      --release /tmp/chisel-release \
      --root /rootfs \
      --arch "${chisel_arch}" \
      base-files_release-info \
      base-files_chisel \
      ca-certificates_data \
      libc6_libs; \
    test -s /rootfs/var/lib/chisel/manifest.wall; \
    test ! -e /rootfs/var/lib/dpkg/status; \
    test ! -e /rootfs/var/lib/dpkg/status.d

FROM scratch
COPY --from=cutter /rootfs /
COPY sentinel.txt /opt/copa-fixture/sentinel.txt

LABEL org.opencontainers.image.title="Copa native Chisel integration fixture"
LABEL sh.copa.fixture.layout="native-chisel"
