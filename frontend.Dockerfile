
# syntax=docker/dockerfile:1

# GO_VERSION should be kept in sync with the `go` directive in go.mod.
# The release workflow passes this automatically via --build-arg
# GO_VERSION=$(awk '/^go /{print $2; exit}' go.mod). This default is a fallback
# for local builds and should match go.mod.
ARG GO_VERSION=1.25.11
ARG ALPINE_VERSION=3.23

FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /src

# Copy go mod files
COPY go.mod go.sum ./

# Copy source code
COPY . .

# Build the frontend binary with cache mounts for faster builds
RUN --mount=type=cache,id=gomod,target=/go/pkg/mod \
    --mount=type=cache,id=gocache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /copa-frontend ./cmd/frontend

# Final image
#
# Distroless static gives us a minimal rootfs (no shell, no package
# manager) while still providing /tmp, CA certs, /etc/passwd, and
# tzdata -- which the frontend needs at runtime (e.g. os.MkdirTemp
# requires /tmp to exist). Do not switch to `FROM scratch` without
# adding those back.
FROM gcr.io/distroless/static-debian12:nonroot AS frontend

# Copy the frontend binary
COPY --from=builder /copa-frontend /copa-frontend

# Add BuildKit frontend capability labels
LABEL moby.buildkit.frontend.network.none="true"
LABEL moby.buildkit.frontend.caps="moby.buildkit.frontend.inputs,moby.buildkit.frontend.contexts"

# Set the entrypoint
ENTRYPOINT ["/copa-frontend"]
