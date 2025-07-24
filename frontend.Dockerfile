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
FROM alpine:3.18

# Install runtime dependencies (for patch operations)
RUN apk add --no-cache ca-certificates busybox

# Copy the frontend binary
COPY --from=builder /copa-frontend /usr/bin/copa-frontend

# Set the entrypoint
ENTRYPOINT ["/usr/bin/copa-frontend"]
