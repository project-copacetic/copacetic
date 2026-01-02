---
title: Distroless Images
---

Copa supports patching distroless container images that lack package managers. This page explains how distroless patching works and which image types are supported.

## Overview

[Distroless images](https://github.com/GoogleContainerTools/distroless) are minimal container images that contain only the application and its runtime dependencies, without package managers, shells, or other OS utilities. While this reduces the attack surface, it traditionally makes patching vulnerabilities more difficult.

Copa solves this by using a **tooling container** approach: it spins up a separate container with the necessary package management tools, downloads and processes the required updates, then copies the patched binaries to the target distroless image.

## Supported Distroless Images

### DPKG-based (Debian)

Copa supports patching Debian-based distroless images, including:

- Google's distroless images (`gcr.io/distroless/*`)
- Custom Debian-based distroless images

For these images, Copa uses a Debian tooling image matching the target's version to process package updates.

### RPM-based (Azure Linux / CBL-Mariner)

Copa supports patching RPM-based distroless images, including:

- Azure Linux distroless (`mcr.microsoft.com/azurelinux/distroless/base`)
- CBL-Mariner distroless (`mcr.microsoft.com/cbl-mariner/distroless/base`)

For these images, Copa uses the corresponding Azure Linux or CBL-Mariner tooling image.

## Unsupported Distroless Images

### Alpine-based Distroless

Copa does not support patching distroless Alpine images. Alpine images that include the `apk` package manager can be patched normally.

### Chainguard Images

Copa does not support Chainguard's wolfi-based images.

## How It Works

When Copa detects a distroless image, it follows this process:

1. **Detection**: Copa probes the target image to identify its OS type and determine if it's a distroless variant by checking for package manager status files.

2. **Tooling Container**: Copa creates a tooling container based on the same OS distribution as the target image. For example:
   - Debian distroless images use a `debian:*-slim` tooling image
   - Azure Linux distroless images use `ghcr.io/project-copacetic/copacetic/azurelinux/base/core` tooling image

3. **Package Processing**: The tooling container downloads the required security update packages and processes them.

4. **Binary Deployment**: Copa copies only the updated binaries from the tooling container to the target distroless image, creating a new patch layer.

5. **Layer Optimization**: The resulting image contains only the original layers plus a single patch layer with the security updates.

## Usage Example

Patching a distroless image works the same as patching any other image:

```bash
# Pull the distroless image
docker pull mcr.microsoft.com/cbl-mariner/distroless/base:2.0

# Generate vulnerability report
trivy image --vuln-type os --ignore-unfixed -f json -o scan.json \
  mcr.microsoft.com/cbl-mariner/distroless/base:2.0

# Patch the image
copa patch \
  -i mcr.microsoft.com/cbl-mariner/distroless/base:2.0 \
  -r scan.json \
  -t 2.0-patched
```

The patched image (`mcr.microsoft.com/cbl-mariner/distroless/base:2.0-patched`) will contain the security updates while maintaining the minimal distroless characteristics.

## Limitations

- **No shell access**: Since distroless images lack shells, Copa cannot execute commands directly in the target image. All package operations happen in the tooling container.

- **Package availability**: Updates are limited to packages available in the distribution's official repositories.

- **OS version matching**: The tooling container must match the target image's OS version. If Copa cannot determine the exact version, patching may fail.

## Troubleshooting

### "No upgradable packages found"

This message indicates that either:
- There are no vulnerable packages with available updates
- The vulnerability scanner report doesn't contain fixable vulnerabilities

### Tooling image pull failures

If Copa fails to pull the tooling image, ensure you have network access to the container registry hosting the tooling images. See the [FAQ](./faq.md#how-does-copa-determine-what-tooling-image-to-use) for details on which tooling images are used.
