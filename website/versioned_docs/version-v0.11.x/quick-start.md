---
title: Quick Start
---

This guide walks you through patching container vulnerabilities using Copa. You'll learn how to scan an image for vulnerabilities, apply security patches, and verify the results.

## What You'll Learn

- How to scan container images for OS-level vulnerabilities
- Two patching strategies: comprehensive vs. targeted patching
- How to verify successful patching and test patched images

## Prerequisites

Before you begin, ensure you have:

- **Copa CLI** - Follow the [installation guide](./installation.md) to build and install Copa
- **Container Runtime** - Copa supports both Docker and Podman:
  - **Docker** - Docker running with CLI installed ([installation guide](https://docs.docker.com/desktop/linux/install/#generic-installation-steps))
  - **Podman** - Podman running with CLI installed ([installation guide](https://podman.io/docs/installation))
- **BuildKit instance** - Copa auto-detects available instances in this order:
  1. Docker's built-in BuildKit (requires Docker v24.0+ with [containerd image store](https://docs.docker.com/storage/containerd/#enable-containerd-image-store-on-docker-engine) enabled for local images)
  2. Current buildx builder (create one with `docker buildx create --use`)
  3. BuildKit daemon at `/run/buildkit/buildkitd.sock` (see [custom addresses](custom-address.md) for examples)
- **Trivy CLI** (optional) - For vulnerability scanning ([installation guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/))

:::info
For advanced BuildKit configurations, see [custom BuildKit addresses](custom-address.md).
:::

## Tutorial

This tutorial demonstrates patching the nginx:1.21.6 image, which contains numerous vulnerabilities.

:::tip
This tutorial shows Docker commands, but Copa works with both Docker and Podman. Where Docker commands are shown, you can substitute `podman` for `docker` in most cases.
:::

### Step 1: Set up the Environment

First, set the image we'll be working with:

```bash
export IMAGE=docker.io/library/nginx:1.21.6
```

:::tip

If you want to patch an image using the digest, you can specify the digest like this:

```bash
export IMAGE=docker.io/library/nginx@sha256:25dedae0aceb6b4fe5837a0acbacc6580453717f126a095aa05a3c6fcea14dd4
```

:::

Copa automatically detects and connects to an available BuildKit instance. If you need a specific instance, see [custom BuildKit addresses](custom-address.md).

### Step 2: Scan for Vulnerabilities

Scan the image to identify OS-level vulnerabilities:

```bash
trivy image --vuln-type os --ignore-unfixed $IMAGE
```

**Expected output:**

```text
nginx:1.21.6 (debian 11.3)
==========================
Total: 207 (UNKNOWN: 0, LOW: 12, MEDIUM: 104, HIGH: 76, CRITICAL: 15)
```

### Step 3: Choose Your Patching Strategy

Copa offers two patching approaches:

#### Option A: Comprehensive Patching

Update all outdated packages to their latest versions:

```bash
copa patch -i $IMAGE
```

:::warning
This approach provides the most comprehensive security updates but may introduce compatibility issues. Always test patched images thoroughly before production use.
:::

#### Option B: Targeted Patching

Update only packages with known vulnerabilities:

1. Generate a vulnerability report:

   ```bash
   trivy image --vuln-type os --ignore-unfixed -f json -o nginx-report.json $IMAGE
   ```

2. Patch using the vulnerability report:

   ```bash
   copa patch -r nginx-report.json -i $IMAGE
   ```

Both methods create a new image tagged `nginx:1.21.6-patched` in your local registry.

:::tip

The image used in this tutorial is a multi-platform image containing many different platforms. To learn more about multi-platform patching, see [multi-platform patching](./multiplatform-patching.md) docs.

:::

### Step 4: Verify the Patch

Scan the patched image to confirm vulnerabilities were resolved:

```bash
trivy image --vuln-type os --ignore-unfixed $IMAGE-patched
```

**Expected output:**

```text
nginx:1.21.6-patched (debian 11.10)
===================================
Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)
```

### Step 5: Test the Patched Image

Verify the patched image works correctly:

```bash
docker run -d --name test-nginx -p 8080:80 $IMAGE-patched
```

Test that nginx is responding:

```bash
curl -I http://localhost:8080
```

**Expected output:**

```text
HTTP/1.1 200 OK
Server: nginx/1.21.6
```

Clean up:

```bash
docker stop test-nginx && docker rm test-nginx
```

### Step 6: Inspect the Changes (Optional)

View the patch layer added by Copa:

```bash
# Using Docker
docker history $IMAGE-patched --format "table {{.ID}}\t{{.CreatedSince}}\t{{.Size}}\t{{.Comment}}"
```

The first entry shows the patch layer with security updates.

## Summary

You've successfully:

1. ✅ Scanned a container image for vulnerabilities
2. ✅ Applied security patches using Copa
3. ✅ Verified the patched image is secure and functional
4. ✅ Learned about different patching strategies

The patched image `nginx:1.21.6-patched` is now ready for use with all known OS vulnerabilities resolved.

## Next Steps

- Learn about [scanner plugins](./scanner-plugins.md) for custom vulnerability sources
- Explore [custom BuildKit configurations](./custom-address.md)
- Read [best practices](./best-practices.md) for production use
- Check out the [Copa Action](./copa-action.md) for GitHub Action integration
- Check out the [Docker Extension](./docker-extension.md) for GUI-based patching


