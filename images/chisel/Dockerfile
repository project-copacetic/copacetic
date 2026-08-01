# syntax=docker/dockerfile:1.7

# The runtime image is intentionally assembled from Alpine so the same recipe
# covers every Chisel architecture Copa supports, including linux/386 and
# linux/riscv64. The published image must be consumed by immutable digest.
ARG GO_IMAGE=golang:1.25.11-alpine
ARG ALPINE_IMAGE=alpine:3.23

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS builder
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG CHISEL_VERSION=v1.4.2
ARG CHISEL_COMMIT=1262471cb663f57f3e201f100019f9bf5b4a7d4f
RUN apk add --no-cache ca-certificates git
WORKDIR /src
RUN git clone https://github.com/canonical/chisel.git chisel \
    && cd chisel \
    && git checkout --detach "${CHISEL_COMMIT}" \
    && test "$(git rev-parse HEAD)" = "${CHISEL_COMMIT}"
WORKDIR /src/chisel
RUN go generate ./cmd ./internal/deb
RUN case "${TARGETARCH}/${TARGETVARIANT}" in \
      arm/v7) export GOARCH=arm GOARM=7 ;; \
      arm/*) echo "unsupported target ${TARGETARCH}/${TARGETVARIANT}" >&2; exit 1 ;; \
      *) export GOARCH="${TARGETARCH}" ;; \
    esac \
    && CGO_ENABLED=0 GOOS="${TARGETOS}" go build -trimpath -ldflags='-s -w' -o /out/chisel ./cmd/chisel

WORKDIR /src/validator
COPY images/chisel/validator/main.go ./main.go
RUN case "${TARGETARCH}/${TARGETVARIANT}" in \
      arm/v7) export GOARCH=arm GOARM=7 ;; \
      arm/*) echo "unsupported target ${TARGETARCH}/${TARGETVARIANT}" >&2; exit 1 ;; \
      *) export GOARCH="${TARGETARCH}" ;; \
    esac \
    && CGO_ENABLED=0 GOOS="${TARGETOS}" go build -trimpath -ldflags='-s -w' -o /out/copa-chisel-validate ./main.go

FROM ${ALPINE_IMAGE}
ARG CHISEL_VERSION=v1.4.2
ARG CHISEL_COMMIT=1262471cb663f57f3e201f100019f9bf5b4a7d4f
RUN apk add --no-cache busybox ca-certificates git zstd \
    && rm -rf /var/cache/apk/* /root/.cache /root/.gitconfig
COPY --from=builder /out/chisel /usr/local/bin/chisel
COPY --from=builder /out/copa-chisel-validate /usr/local/bin/copa-chisel-validate
LABEL org.opencontainers.image.title="Copacetic Chisel tooling" \
      org.opencontainers.image.source="https://github.com/project-copacetic/copacetic" \
      org.opencontainers.image.version="${CHISEL_VERSION}" \
      sh.copa.chisel.commit="${CHISEL_COMMIT}"
ENTRYPOINT ["/usr/local/bin/chisel"]
