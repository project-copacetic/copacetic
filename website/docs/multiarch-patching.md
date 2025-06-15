---
title: Multi-Platform Patching
---

Copa also supports patching multi-platform container images, streamlining the process of securing applications deployed across diverse hardware platforms. This guide explains how Copa handles multi-platform images and how you can use this feature.

## Usage

To patch a multi-platform image, you can use the `copa patch` command with the `--report` flag pointing to a directory (which tells Copa this will be a multi-platform patch) along with flags to specify your image, and desired output tag.

### Create vulnerability reports for multi-platform images

Before you can patch a multi-platform image, you need to generate vulnerability reports for each platform architecture. You can do this using `trivy` using `--platform` flag to specify the architecture. Below is an example of how to generate vulnerability reports for a multi-platform image like `nginx:1.25.0`.

```bash
export IMAGE=docker.io/library/nginx:1.25.0 # Replace with your multi-platform image

mkdir -p reports

trivy image --vuln-type os --scanners vuln --ignore-unfixed \
  -f json -o reports/amd64.json \
  --platform linux/amd64 $IMAGE
trivy image --vuln-type os --scanners vuln --ignore-unfixed \
  -f json -o reports/arm64.json \
  --platform linux/arm64 $IMAGE
```

This will create two JSON files in the `reports` directory, one for each architecture (`amd64` and `arm64`).

### Patching Multi-Platform Images

To patch a multi-platform image, you can use the `copa patch` command with the `--image` flag to specify the multi-platform image, the `--report` flag to point to the directory containing your vulnerability reports, and optionally a `--tag` for the final patched image.

```bash
copa patch \
  --image $IMAGE \
  --report reports
```

Key Flags for Multi-Platform Patching:

- `--report <directory_path>`: Specifies the directory containing platform-specific vulnerability reports.
- `--tag <final_tag>` (optional): The tag for the final, reassembled multi-platform manifest (e.g., `1.0-patched`).
- `--push` (optional): If included, Copa pushes the final multi-platform manifest to the registry.
- `--ignore-errors` (optional, default: `false`): When `false` (default), Copa warns about errors and fails if any platform encounters an error. When `true`, Copa warns about errors but continues processing other platforms.

### Things to Keep in Mind

If you don't provide a `--report` flag pointing to a directory, Copa will not perform multi-platform patching and will instead only patch the image for the architecture of the host machine.

If `--push` is not specified, the individual patched images will be saved locally, and you can push them to your registry later using `docker push` and then `docker manifest create/push` to create the multi-platform manifest.

---

## Emulation and QEMU for Cross-Platform Patching ⚙️

When patching an image for an architecture different from your host machine's architecture (e.g., patching an `arm64` image on an `amd64` machine), Copa relies on **emulation**. This is often necessary for multi-platform image patching, as you might not have native hardware for every architecture you intend to patch.

Copa leverages **BuildKit**, which in turn can use **QEMU** for emulation. QEMU is a generic and open-source machine emulator and virtualizer. When BuildKit detects that it needs to execute binaries for a foreign architecture, it can use QEMU user-mode emulation to run those commands.

### Why Emulation is Needed

- **Running Package Managers:** To apply patches, Copa needs to execute the package manager (like `apk`, `apt`, `yum`) _inside_ the environment of the target image's architecture. If you're on an `amd64` host trying to patch an `arm64` image, the `arm64` package manager won't run natively. QEMU bridges this gap.
- **Ensuring Correctness:** Emulation helps ensure that the patches are applied in an environment that closely mirrors the target architecture, reducing the chances of incompatibilities.

### Setting up QEMU

**Docker Desktop (macOS and Windows) comes pre-configured with QEMU emulation support and requires no additional setup.**

For Linux hosts or when using BuildKit outside of Docker Desktop, your host system  (where the `copa` command and BuildKit daemon are running) needs to have QEMU static binaries registered with the kernel's `binfmt_misc` handler. This allows the kernel to automatically invoke QEMU when it encounters a binary for a foreign architecture.

**Installation Steps (Linux/Non-Docker Desktop environments):**

One way to set this up, especially in Dockerized environments or on Linux hosts, is to use the `multiarch/qemu-user-static` image:

1. **Ensure your kernel supports `binfmt_misc`:** Most modern Linux kernels do.

2. **Register QEMU handlers:** You can do this by running the `multiarch/qemu-user-static` Docker image with privileged mode:

    ```bash
    docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
    ```
