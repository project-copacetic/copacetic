# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /src

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the frontend binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /copa-frontend ./cmd/frontend

# Final image
FROM scratch

# Copy CA certificates for HTTPS connections
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the frontend binary
COPY --from=builder /copa-frontend /copa-frontend

# Add BuildKit frontend capability labels
LABEL moby.buildkit.frontend.network.none="true"
LABEL moby.buildkit.frontend.caps="moby.buildkit.frontend.inputs,moby.buildkit.frontend.subrequests,moby.buildkit.frontend.contexts"

# Set the entrypoint
ENTRYPOINT ["/copa-frontend"]
