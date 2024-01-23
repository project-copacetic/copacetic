---
title: Custom buildkit addresses
---

If you need to specify a custom address using the `--addr` flag. Here are the supported formats:

- `unix:///path/to/buildkit.sock` - Connect to buildkit over unix socket.
- `tcp://$BUILDKIT_ADDR:$PORT` - Connect to buildkit over TCP. (not recommended for security reasons)
- `docker://<docker connection spec>` - Connect to docker, currently only unix sockets are supported, e.g. `docker://unix:///var/run/docker.sock` (or just `docker://`).
- `docker-container://my-buildkit-container` - Connect to a buildkitd running in a docker container.
- `buildx://my-builder` - Connect to a buildx builder (or `buildx://` for the currently selected builder). *Note: only container-backed buildx instances are currently supported*
- `nerdctl-container://my-container-name` - Similar to `docker-container` but uses `nerdctl`.
- `podman-container://my-container-name` - Similar to `docker-container` but uses `podman`.
- `ssh://myhost` - Connect to a buildkit instance over SSH. Format of the host spec should mimic the SSH command.
- `kubepod://mypod` - Connect to buildkit running in a Kubernetes pod. Can also specify kubectl context and pod namespace (`kubepod://mypod?context=foo&namespace=notdefault`).

## Buildkit Connection Examples

### Option 1: Connect using defaults

```bash
copa patch -i docker.io/library/nginx:1.21.6 -r nginx.1.21.6.json -t 1.21.6-patched
```

### Option 2: Connect to buildx

```bash
docker buildx create --name demo
copa patch -i docker.io/library/nginx:1.21.6 -r nginx.1.21.6.json -t 1.21.6-patched --addr buildx://demo
```

### Option 3: Buildkit in a container

```bash
export BUILDKIT_VERSION=v0.12.4
docker run \
    --detach \
    --rm \
    --privileged \
    --name buildkitd \
    --entrypoint buildkitd \
    "moby/buildkit:$BUILDKIT_VERSION"

copa patch -i docker.io/library/nginx:1.21.6 -r nginx.1.21.6.json -t 1.21.6-patched --addr docker-container://buildkitd
```

### Option 4: Buildkit over TCP

```bash
export BUILDKIT_VERSION=v0.12.4
export BUILDKIT_PORT=8888
docker run \
    --detach \
    --rm \
    --privileged \
    -p 127.0.0.1:$BUILDKIT_PORT:$BUILDKIT_PORT/tcp \
    --name buildkitd \
    --entrypoint buildkitd \
    "moby/buildkit:$BUILDKIT_VERSION" \
    --addr tcp://0.0.0.0:$BUILDKIT_PORT

copa patch \
    -i docker.io/library/nginx:1.21.6 \
    -r nginx.1.21.6.json \
    -t 1.21.6-patched \
    -a tcp://0.0.0.0:$BUILDKIT_PORT
```
