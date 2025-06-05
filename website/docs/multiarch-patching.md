---
title: Multi-Arch Patching
---

# Multi-Arch Patching

Copa also supports patching multi-architecture container images, streamlining the process of securing applications deployed across diverse hardware platforms. This guide explains how Copa handles multi-arch images and how you can use this feature.

## Usage

To patch a multi-architecture image, you can use the `copa patch` command with the `--report-directory` flag (which tells Copa this will be a multi-arch patch) along with flags to specify your image, and desired output tag.

Basic Command Structure:

```bash
copa patch \
  --image <your-multi-arch-image> \
  --report-directory <path-to-your-reports-directory> \
  --tag <desired-patched-image-tag> \
  [--push] \
  [--platform-specific-errors <fail|warn|skip>] \
```

Key Flags for Multi-Arch Patching:

- `--report-directory <directory_path>`: Specifies the directory containing platform-specific vulnerability reports.
- `--tag <final_tag>` (optional): The tag for the final, reassembled multi-arch manifest (e.g., `1.0-patched`).
- `--push` (optional): If included, Copa pushes the final multi-arch manifest to the registry.
- `--platform-specific-errors <fail|warn|skip>` (optional, default: `skip`): Determines how Copa handles errors encountered while patching an individual platform's sub-image.

### Example:

To patch a multi-arch image `myregistry.io/app:1.2` using reports from the `./scan_results` directory, tag the patched image as `myregistry.io/app:1.2-patched`, and push it to the registry:

```bash
copa patch \
  --image myregistry.io/app:1.2 \
  --report-directory ./scan_results \
  --tag 1.2-patched \
  --push
```

When patching `myregistry.io/app:1.2`, Copa first determines the image’s supported architectures, then walks the report directory and patches only those scan reports whose architectures match.

### Things to Keep in Mind

If you don't include the `--report-directory` flag, Copa will not perform multi-arch patching and will instead only patch the image for the architecture of the host machine.

If `--push` is not specified, the individual patched images will be saved locally, and you can push them to your registry later using `docker push` and then `docker manifest create/push` to create the multi-arch manifest.

---

## Emulation and QEMU for Cross-Platform Patching ⚙️

When patching an image for an architecture different from your host machine's architecture (e.g., patching an `arm64` image on an `amd64` machine), Copa relies on **emulation**. This is often necessary for multi-arch image patching, as you might not have native hardware for every architecture you intend to patch.

Copa leverages **BuildKit**, which in turn can use **QEMU** for emulation. QEMU is a generic and open-source machine emulator and virtualizer. When BuildKit detects that it needs to execute binaries for a foreign architecture, it can use QEMU user-mode emulation to run those commands.

### Why Emulation is Needed:

- **Running Package Managers:** To apply patches, Copa needs to execute the package manager (like `apk`, `apt`, `yum`) _inside_ the environment of the target image's architecture. If you're on an `amd64` host trying to patch an `arm64` image, the `arm64` package manager won't run natively. QEMU bridges this gap.
- **Ensuring Correctness:** Emulation helps ensure that the patches are applied in an environment that closely mirrors the target architecture, reducing the chances of incompatibilities.

### Setting up QEMU:

**Docker Desktop (macOS and Windows) comes pre-configured with QEMU emulation support and requires no additional setup.**

For Linux hosts or when using BuildKit outside of Docker Desktop, your host system  (where the `copa` command and BuildKit daemon are running) needs to have QEMU static binaries registered with the kernel's `binfmt_misc` handler. This allows the kernel to automatically invoke QEMU when it encounters a binary for a foreign architecture.

**Installation Steps (Linux/Non-Docker Desktop environments):**

One way to set this up, especially in Dockerized environments or on Linux hosts, is to use the `multiarch/qemu-user-static` image:

1.  **Ensure your kernel supports `binfmt_misc`:** Most modern Linux kernels do.

2.  **Register QEMU handlers:** You can do this by running the `multiarch/qemu-user-static` Docker image with privileged mode:

    ```bash
    docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
    ```
