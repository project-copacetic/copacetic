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

Native Chisel re-cuts have one narrower exception: `linux/arm/v6` is not
supported for images that use `/var/lib/chisel/manifest.wall`. See
[Ubuntu Chiseled Images](./chiseled-images.md#platforms-and-provenance).

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
  trivy image --pkg-types os --scanners vuln --ignore-unfixed \
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

| Flag              | Description                                                     | Example                              |
| ----------------- | --------------------------------------------------------------- | ------------------------------------ |
| `--platform`      | Specifies which platforms to patch from manifest list           | `--platform linux/amd64,linux/arm64` |
| `--report`        | One report file or a directory of platform-specific reports      | `--report ./platform-reports/`       |
| `--ignore-errors` | Continue patching other platforms if one fails                  | `--ignore-errors`                    |
| `--push`          | Push all manifests and index/manifest list to registry          | `--push`                             |
| `--oci-dir`       | Export multi-platform index/manifest as OCI layout directory    | `--oci-dir ./output-directory`       |

## Multi-Platform Behavior

- **Automatic platform detection**: Copa automatically detects whether an image is multi-platform (Docker manifest list or OCI Index) or single-platform and handles them accordingly.

- **Report and platform flags**: With one report file, pass zero or one `--platform` value; an explicit value is honored and must match the report architecture, while multiple values are rejected. If it is omitted, Copa determines the platform from the report metadata and uses the host's default Linux platform only as a fallback. With a report directory, platforms are determined from the reports and `--platform` is ignored. Without a report, `--platform` can select any subset of discovered platforms.

- **Platform preservation**: When using `--platform`, only specified platforms are patched; others are preserved unchanged in a pushed index or an OCI layout.

- **OCI layout export**: The `--oci-dir` flag creates a complete local OCI Image Layout containing the output index, patched platforms, and unchanged platform descriptors and blobs. Use it when not pushing to a registry. `--push` and `--oci-dir` cannot be used together.

- **Normal local image loading**: Without `--push` or `--oci-dir`, Copa loads the individually patched platform images into the local runtime. Unchanged platforms remain available from the source registry but are not loaded locally.

- **No-report platform discovery**: In comprehensive no-report mode, Copa inspects the image. A single-platform image is patched as that discovered platform; otherwise the selected or discovered multi-platform set is used.

:::note
**Report-based vs. Platform-based patching:**

- With a report directory, only platforms with vulnerability reports are patched. Other platforms pass through unchanged in the pushed index or OCI layout.

- With one report file, Copa performs a single-platform patch. An optional single `--platform` value selects that platform explicitly; otherwise Copa uses the platform in the report metadata, falling back to the host's default Linux platform only when the report does not identify one.

- When using `--platform` without a report, only the specified platforms are patched, and others are preserved unchanged in the pushed index or OCI layout.

- When using neither flag, Copa patches all available platforms if the image is multi-platform.

:::

:::warning
Build attestations, signatures, and OCI referrers from the original image are not preserved or copied to the patched image.
:::

## Understanding the Results
 
After a multi-platform run, Copa prints a tabular summary so you can quickly see what happened for each platform. 
A typical example looks like (including a failure case):

```text
Multi-arch patch summary:
PLATFORM        STATUS   REFERENCE                                        MESSAGE
linux/amd64     Patched  docker.io/library/nginx:1.27.1-patched-amd64     Successfully patched image (linux/amd64)
linux/arm/v7    Patched  docker.io/library/nginx:1.27.1-patched-arm-v7    Successfully patched image (linux/arm/v7)
linux/arm64     Patched  docker.io/library/nginx:1.27.1-patched-arm64     Successfully patched image (linux/arm64)
linux/386       Error    -                                                Emulation is not enabled for platform linux/386
linux/mips64le  Patched  docker.io/library/nginx:1.27.1-patched-mips64le  Successfully patched image (linux/mips64le)
linux/ppc64le   Patched  docker.io/library/nginx:1.27.1-patched-ppc64le   Successfully patched image (linux/ppc64le)
linux/s390x     Patched  docker.io/library/nginx:1.27.1-patched-s390x     Successfully patched image (linux/s390x)
```
In this example, the linux/386 platform failed with Error because QEMU emulation is not enabled on the host.
If you see a similar error, follow the steps in [Cross-Platform Emulation Setup](#cross-platform-emulation-setup) to enable emulation and then rerun the patch.

## Cross-Platform Emulation Setup

When patching images for architectures different from your host machine (e.g., patching ARM64 images on an AMD64 host), Copa uses QEMU emulation through BuildKit.

### Why Emulation is Required

#### Package Manager Execution

- Copa executes package managers (`apt`, `yum`, `apk`, `zypper`) inside the target architecture environment
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
