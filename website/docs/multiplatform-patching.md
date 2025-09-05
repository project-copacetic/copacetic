---
title: Multi-Platform Patching
---

This guide covers Copa's multi-platform patching capabilities for securing applications across diverse hardware platforms.

## Overview

[Multi-platform images](https://docs.docker.com/build/building/multi-platform/) contain multiple platform-specific variants of the same application. Copa can automatically detect and patch these images across all supported platforms or target specific architectures based on your needs.

### Supported Architectures

Copa supports patching the following platforms:

| Platform        | Description                              |
| --------------- | ---------------------------------------- |
| `linux/amd64`   | 64-bit x86 (Intel/AMD)                   |
| `linux/arm64`   | 64-bit ARM (Apple Silicon, AWS Graviton) |
| `linux/arm/v7`  | 32-bit ARM v7                            |
| `linux/arm/v6`  | 32-bit ARM v6                            |
| `linux/386`     | 32-bit x86                               |
| `linux/ppc64le` | PowerPC 64-bit Little Endian             |
| `linux/s390x`   | IBM System z                             |
| `linux/riscv64` | 64-bit RISC-V                            |

:::note
Any platform not listed above (such as `windows/amd64`) is not supported by Copa for patching. However, they'll be always be preserved as is if they exist in the original manifest.
:::

## Multi-Platform Patching Strategies

Copa offers several approaches for multi-platform patching, each optimized for different use cases:

### Report-Based Patching

Generate platform-specific vulnerability reports and patch only affected platforms:

```bash
# Generate reports for specific platforms
export IMAGE=docker.io/library/nginx:1.25.0
mkdir -p reports

# Create platform-specific reports
export PLATFORMS="linux/amd64 linux/arm64"
for platform in $PLATFORMS; do
  arch=$(echo $platform | cut -d'/' -f2 | sed 's/\//-/g')
  echo "Scanning $platform..."
  trivy image --vuln-type os --scanners vuln --ignore-unfixed \
    -f json -o reports/${arch}.json --image-src remote --platform $platform $IMAGE || \
    echo "Warning: Failed to scan $platform"
done

# Patch only platforms with reports
copa patch --image $IMAGE --report reports --tag nginx:1.25.0-patched
```

### Platform-Selective Patching

Target specific platforms:

```bash
# Patch only linux/amd64 and linux/arm64 platforms
# Rest of the platforms will be preserved unchanged
copa patch --image $IMAGE \
  --platform linux/amd64,linux/arm64 \
  --tag nginx:1.25.0-patched

# Patch all available platforms (default behavior)
copa patch --image $IMAGE --tag nginx:1.25.0-patched
```

### Comprehensive Patching

Update all platforms with the latest patches:

```bash
# Patch all platforms in the manifest list
copa patch --image $IMAGE --tag nginx:1.25.0-patched
```

## Multi-Platform Command Reference

### Platform-Specific Flags

These flags are essential for multi-platform patching:

| Flag              | Description                                            | Example                              |
| ----------------- | ------------------------------------------------------ | ------------------------------------ |
| `--platform`      | Specifies which platforms to patch from manifest list  | `--platform linux/amd64,linux/arm64` |
| `--report`        | Directory with platform-specific vulnerability reports | `--report ./platform-reports/`       |
| `--ignore-errors` | Continue patching other platforms if one fails         | `--ignore-errors`                    |
| `--push`          | Push all manifests and index/manifest list to registry | `--push`                             |

## Multi-Platform Behavior

- **Automatic platform detection**: Copa automatically detects whether an image is multi-platform (Docker manifest list or OCI Index) or single-platform and handles them accordingly.

- **Report vs. platform flags**: The `--platform` flag is only available when not using `--report`. When using `--report`, platforms are determined by the reports available.

- **Platform preservation**: When using `--platform`, only specified platforms are patched; others are preserved unchanged in the final manifest.

- **No local storage for unspecified platforms**: If `--push` is not specified, the individual patched images will be saved locally, but preserved platforms will only exist in the registry.

- **Single-platform fallback**: If you don't provide a `--report` directory and don't use `--platform`, Copa will detect if the image is single-platform and patch only that platform.

:::note
**Report-based vs. Platform-based patching:**

- When using `--report`, Copa copies over unpatched platforms as a passthrough - only platforms with vulnerability reports are patched, while other platforms remain unchanged in the final multi-platform image.

- When using `--platform`, only the specified platforms are patched, and others are preserved unchanged.

- When using neither flag, Copa patches all available platforms if the image is multi-platform.

:::

:::warning
Build attestations, signatures, and OCI referrers from the original image are not preserved or copied to the patched image.
:::

## Cross-Platform Emulation Setup

When patching images for architectures different from your host machine (e.g., patching ARM64 images on an AMD64 host), Copa uses QEMU emulation through BuildKit.

### Why Emulation is Required

#### Package Manager Execution

- Copa executes package managers (`apt`, `yum`, `apk`) inside the target architecture environment
- Native binaries for foreign architectures cannot run without emulation
- QEMU provides transparent binary translation

#### Architecture Compatibility

- Ensures patches are applied correctly for the target architecture
- Prevents compatibility issues between different instruction sets
- Maintains image integrity across platforms

### Setup Requirements

#### Docker Desktop Users (macOS/Windows)

**No setup required** - QEMU emulation is pre-configured and ready to use.

#### Linux

QEMU static binaries must be registered with the kernel's `binfmt_misc` handler:

```bash
# Install QEMU emulation support
docker run --privileged --rm tonistiigi/binfmt --install all

# Verify installation
ls /proc/sys/fs/binfmt_misc/qemu-*
```

For more details, see [Docker's QEMU documentation](https://docs.docker.com/build/building/multi-platform/#qemu).
