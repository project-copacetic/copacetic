---
title: Multi-Arch Patching
---

# Multi-Arch Patching

Copa also supports patching multi-architecture container images, streamlining the process of securing applications deployed across diverse hardware platforms. This guide explains how Copa handles multi-arch images and how you can use this feature.

## Usage

To patch a multi-architecture image, you can use the copa patch command with the `--report-directory` flag (which tells Copa this will be a multi-arch patch) along with flags to specify your image, and desired output tag.

Basic Command Structure:

```bash
copa patch \
 --image <your-multi-arch-image> \
 --report-dir <path-to-your-reports-directory> \
 --tag <desired-patched-image-tag> \
 [--push] \
 [--platform-specific-errors <fail|warn|skip>] \
```

Key Flags for Multi-Arch Patching:

- `--report-dir <directory_path>`: Specifies the directory containing platform-specific vulnerability reports.

- `--tag <final_tag>`: The tag for the final, reassembled multi-arch manifest (e.g., 1.0-patched).

- `--push` (optional): If included, Copa pushes the final multi-arch manifest to the registry.

- `--platform-specific-errors <fail|warn|skip>` (optional, default: skip): Determines how Copa handles errors encountered while patching an individual platform's sub-image.

### Example:

To patch a multi-arch image myregistry.io/app:1.2 using reports from the ./scan_results directory, tag the patched image as myregistry.io/app:1.2-patched, and push it to the registry:

```bash
copa patch \
 --image myregistry.io/app:1.2 \
 --report-dir ./scan_results \
 --tag 1.2-patched \
 --push
```

When patching `myregistry.io/app:1.2`, Copa first identifies all architectures supported by the image. It then examines the specified report directory to find scan reports for these architectures. Copa will only patch the architectures that are both present in the image and have a corresponding report in the directory.
