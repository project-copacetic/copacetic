---
title: Bulk Image Patching
---

This guide covers Copa's bulk image patching capability for patching many images from a single declarative config. Define repositories, tag discovery rules, and output tagging in YAML, then execute everything with one command.

## Overview

Bulk mode adds a `--config` flag to `copa patch`. Instead of targeting one image, Copa reads a PatchConfig file, discovers tags (via list, pattern, or latest), and runs patch jobs concurrently. This is ideal for nightly sweeps, release hardening, or keeping base images up to date.

:::note
Bulk patching uses Copa's comprehensive update-all flow. Vulnerability report–driven bulk patching is planned for a future release.
:::

## PatchConfig Schema

Top‑level fields:

```yaml
# copa-bulk-config.yaml
apiVersion: copa.sh/v1alpha1
kind: PatchConfig

images:
  - name: "nginx"
    image: "docker.io/library/nginx"
    tags:
      strategy: "pattern"              # pattern | latest | list
      pattern: "^1\\.2[0-9]\\.[0-9]+$"
      maxTags: 3                        # optional cap
      exclude: ["1.20.0", "1.20.1"]   # optional skip list
    target:
      # Defaults to {{ .SourceTag }}-patched if omitted
      tag: "{{ .SourceTag }}-patched"

  - name: "python"
    image: "docker.io/library/python"
    tags:
      strategy: "list"
      list: ["3.9.18", "3.10.13", "3.11.7"]
    # Optional per-image platform filter for multi-arch
    platforms: ["linux/amd64", "linux/arm64"]

  - name: "alpine"
    image: "docker.io/library/alpine"
    tags:
      strategy: "latest"
```

### Tag Strategies

- strategy: list
  - Patch exactly the tags provided in `list`.
  - Missing tags are logged as warnings and skipped.

- strategy: pattern
  - Discover all tags from the registry, filter with a regex `pattern`.
  - Sort with semantic versioning when possible; fall back to lexical as needed.
  - Apply `maxTags` cap and `exclude` list before patching.

- strategy: latest
  - Select a single highest version by semantic versioning (or registry timestamp fallback for non‑semver) and patch only that tag.

## Multi‑Platform Behavior

- Automatic detection: If a discovered tag is multi‑arch, Copa patches all platforms by default, or only those listed in `platforms` for that image spec.
- Targeting platforms: Use `platforms` in the YAML to restrict which platforms are patched; other platforms are preserved unchanged in the final manifest.
- End result: Patched images are pushed when `--push` is set, or exported to OCI layout with `--oci-dir` when not pushing.

See also: [Multi‑Platform Patching](./multiplatform-patching.md)

## Running Bulk Patching

```bash
# Patch everything defined in the config and push results
copa patch --config ./copa-bulk-config.yaml --push --timeout 15m

# Offline export (no push): write multi‑arch index/manifest as OCI layout
copa patch --config ./copa-bulk-config.yaml --oci-dir ./out
```

### Command Reference (Bulk Mode)

| Flag            | Description                                                              |
| --------------- | ------------------------------------------------------------------------ |
| `--config`      | Path to PatchConfig YAML. Enables bulk mode.                             |
| `--push`        | Push patched images and (if multi‑arch) the manifest list to the registry|
| `--timeout`     | Per‑job timeout (e.g., `15m`)                                            |
| `--ignore-errors` | Continue processing other jobs if one fails                           |
| `--oci-dir`     | Export patched image(s) as an OCI layout instead of pushing              |

Restrictions in bulk mode:

- `--config` cannot be combined with `--image`, `--report`, or `--tag`.
- Global flags like `--push`, `--timeout`, `--ignore-errors`, and `--oci-dir` apply to every job defined by the config.

## Behavior and Output

- Concurrency: Copa runs a worker pool to process many images/tags in parallel without overwhelming the host.
- Target tags: If `target.tag` is omitted, Copa uses `{{ .SourceTag }}-patched` (e.g., `1.21.6-patched`).
- Summary: At the end, Copa prints a summary table listing each `image:tag`, status, and details.
- Failures: Individual job failures are reported; with `--ignore-errors`, other jobs continue.

## Examples

### Nightly sweep

Patch the three latest matching minor versions for nginx and all specified python versions, push results:

```bash
copa patch --config ./copa-bulk-config.yaml --push --timeout 20m
```

### Keep base images fresh

Use `pattern` with `maxTags` to continuously patch the latest LTS tags. Example pattern for Ubuntu LTS: `^(20|22|24)\.04$`.

:::warning
Build attestations, signatures, and OCI referrers from the original images are not preserved or copied to the patched images.
:::
