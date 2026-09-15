---
title: Custom BuildKit Addresses
---

Copa automatically detects available BuildKit instances, but you can specify a custom address using the `--addr` flag for advanced configurations or when automatic detection fails.

:::note
When using copacetic with Docker Desktop, you must enable the containerd image store. 
For instructions, please see the official Docker documentation on using the [containerd image store](https://docs.docker.com/engine/storage/containerd/)
:::

## Supported Address Formats

| Format                 | Example                                     | Description                                             |
| ---------------------- | ------------------------------------------- | ------------------------------------------------------- |
| `unix://`              | `unix:///path/to/buildkit.sock`             | Connect to BuildKit over Unix socket                    |
| `tcp://`               | `tcp://127.0.0.1:8888`                      | Connect over TCP (not recommended for production)       |
| `docker://`            | `docker://unix:///var/run/docker.sock`      | Connect to Docker daemon (use `docker://` for default)  |
| `docker-container://`  | `docker-container://my-buildkit-container`  | Connect to BuildKit running in Docker container         |
| `buildx://`            | `buildx://my-builder`                       | Connect to buildx builder (use `buildx://` for current) |
| `nerdctl-container://` | `nerdctl-container://my-container-name`     | Connect via nerdctl to container                        |
| `podman-container://`  | `podman-container://my-container-name`      | Connect via Podman to container                         |
| `ssh://`               | `ssh://user@myhost`                         | Connect to remote BuildKit over SSH                     |
| `kubepod://`           | `kubepod://mypod?context=foo&namespace=bar` | Connect to BuildKit in Kubernetes pod                   |

:::warning
TCP connections without TLS are insecure and should only be used in trusted environments. Always use TLS encryption for production deployments.
:::

## Common Use Cases

### Default Connection (Recommended)

Copa automatically detects the best available BuildKit instance:

```bash
copa patch -i docker.io/library/nginx:1.21.6 -r nginx.1.21.6.json -t 1.21.6-patched
```

### Using a Specific buildx Builder

Create and use a dedicated buildx builder:

```bash
# Create a new builder
docker buildx create --name copa-builder --use

# Use the builder with Copa
copa patch -i docker.io/library/nginx:1.21.6 -r nginx.1.21.6.json -t 1.21.6-patched --addr buildx://copa-builder
```

### BuildKit in a Container

Run BuildKit in a dedicated container:

```bash
# Get the latest BuildKit version from GitHub releases
export BUILDKIT_VERSION=$(curl -s https://api.github.com/repos/moby/buildkit/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
```

#### Docker

```bash
docker run \
    --detach \
    --rm \
    --privileged \
    --name buildkitd \
    --entrypoint buildkitd \
    "moby/buildkit:$BUILDKIT_VERSION"

# Use the containerized BuildKit
copa patch -i docker.io/library/nginx:1.21.6 -r nginx.1.21.6.json -t 1.21.6-patched --addr docker-container://buildkitd
```

#### Podman

```bash
podman run \
    --detach \
    --rm \
    --privileged \
    --name buildkitd \
    --entrypoint buildkitd \
    "moby/buildkit:$BUILDKIT_VERSION"

# Connect Copa to Podman-managed BuildKit
copa patch -i docker.io/library/nginx:1.21.6 -r nginx.1.21.6.json -t 1.21.6-patched --addr podman-container://buildkitd
```
