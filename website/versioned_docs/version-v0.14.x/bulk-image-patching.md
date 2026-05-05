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

# Optional: global default target for all images
target:
  registry: "ghcr.io/myorg"           # Target registry for patched images
  tag: "{{ .SourceTag }}-patched"     # Tag template (default if omitted)

images:
  - name: "nginx"
    image: "docker.io/library/nginx"  # Source registry
    tags:
      strategy: "pattern"              # pattern | latest | list
      pattern: "^1\\.2[0-9]\\.[0-9]+$"
      maxTags: 3                        # optional cap
      exclude: ["1.20.0", "1.20.1"]   # optional skip list
    # Inherits global target (or override per-image)

  - name: "python"
    image: "docker.io/library/python"
    tags:
      strategy: "list"
      list: ["3.9.18", "3.10.13", "3.11.7"]
    # Optional per-image platform filter for multi-arch
    platforms: ["linux/amd64", "linux/arm64"]
    # Optional: override global target for this image
    target:
      registry: "quay.io/special/python"
      tag: "{{ .SourceTag }}-fixed"

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

| Flag                    | Description                                                              |
| ----------------------- | ------------------------------------------------------------------------ |
| `--config`              | Path to PatchConfig YAML. Enables bulk mode.                             |
| `--push`                | Push patched images and (if multi‑arch) the manifest list to the registry|
| `-r`, `--report`        | Directory containing vulnerability reports for patched images (for skip detection) |
| `--timeout`             | Per‑job timeout (e.g., `15m`)                                            |
| `--ignore-errors`       | Continue processing other jobs if one fails                           |
| `--oci-dir`             | Export patched image(s) as an OCI layout instead of pushing              |

Restrictions in bulk mode:

- `--config` cannot be combined with `--image` or `--tag`.
- Global flags like `--push`, `--timeout`, `--ignore-errors`, and `--oci-dir` apply to every job defined by the config.

## Behavior and Output

- Concurrency: Copa runs a worker pool to process many images/tags in parallel without overwhelming the host.
- Target tags: If `target.tag` is omitted, Copa uses `{{ .SourceTag }}-patched` (e.g., `1.21.6-patched`).
- Summary: At the end, Copa prints a summary table listing each `image:tag`, status, and details.
- Failures: Individual job failures are reported; with `--ignore-errors`, other jobs continue.

## Skip Already-Patched Images

Copa can skip re-patching images that already have patched versions with no fixable vulnerabilities. This saves time and compute in scheduled/CI environments.

:::note
This skip feature uses vulnerability reports to decide **whether** to re-patch, not **what** to patch. When patching occurs, Copa still applies comprehensive updates to all packages (update-all flow), not selective patching based on specific CVEs.
:::

### How It Works

When you run `copa patch --config` with `--push` and `-r`:

1. **First run**: Images are patched from the original source (e.g., `nginx:1.25.3`) and pushed with the base tag (e.g., `1.25.3-patched`)
2. **Scan patched images**: Run your scanner (Trivy, etc.) on patched images and save reports to a directory
3. **Subsequent runs with reports**: Copa checks vulnerability reports for existing patched images
   - If report shows no fixable vulnerabilities → skips patching (status: "Skipped")
   - If report shows fixable vulnerabilities → re-patches **from the original source image** with version-bumped tag
   - If report not found → proceeds with patching (fail-open behavior)

**Important**: Re-patches are always created from the original source image (not the previous patched image), ensuring comprehensive updates and preventing layer buildup. The skip feature saves time by avoiding this re-work when no new vulnerabilities are present.

### Report Directory Setup

Copa uses vulnerability reports to determine if patching is needed. You provide reports via the `-r` flag.

**Directory structure:**
```
reports/
  nginx-report.json
  alpine-report.json
  any-filename-you-want.json
```

**How it works:** Copa reads the `ArtifactName` field from inside each report JSON file to match reports to images. You can name your report files anything you want—Copa doesn't rely on filenames.

**Cross-registry workflows:** If you patch images from one registry (e.g., `quay.io/opstree/redis`) but push patched images to a different registry (e.g., `ghcr.io/myorg/redis`), specify the target registry in your config using `target.registry`.

Copa automatically extracts the image name from the source and appends it to the target registry:
- Source: `quay.io/opstree/redis` + Target: `ghcr.io/myorg` → Patched image: `ghcr.io/myorg/redis`
- Source: `docker.io/library/nginx` + Target: `ghcr.io/myorg` → Patched image: `ghcr.io/myorg/nginx`

```yaml
apiVersion: copa.sh/v1alpha1
kind: PatchConfig

# Global target: all patched images go to ghcr.io/myorg
target:
  registry: "ghcr.io/myorg"

images:
  - name: "redis"
    image: "quay.io/opstree/redis"  # Source: quay.io/opstree/redis
    tags:
      strategy: "list"
      list: ["v8.2.1"]
    # Result: patched image pushed to ghcr.io/myorg/redis:v8.2.1-patched
```

This ensures:
- Copa queries `ghcr.io/myorg/redis` for existing patched tags (not the source registry)
- Reports with `ArtifactName: "ghcr.io/myorg/redis:v8.2.1-patched"` match correctly
- Patched images are pushed to the target registry with the correct image name

**Complete workflow:**
```bash
# 1. Initial bulk patch
copa patch --config bulk.yaml --push

# 2. Scan patched images (user's responsibility)
# Name files however you want - Copa reads ArtifactName from the JSON
trivy image registry.io/nginx:1.25.3-patched -f json -o reports/nginx-patched.json
trivy image registry.io/alpine:3.19-patched -f json -o reports/alpine-patched.json

# 3. Run bulk patch with skip detection
copa patch --config bulk.yaml --push -r ./reports
# Skips images with clean reports, re-patches images with vulnerabilities
```

### Scanner Support

The skip detection feature works with **any scanner that Copa supports** through the `--scanner` flag:
- Trivy (default): `--scanner=trivy`
- Native format: `--scanner=native`
- Custom plugins: `--scanner=custom-plugin`

Copa parses the vulnerability reports you provide, making it scanner-agnostic. This maintains separation of concerns: you control when and how scanning happens, Copa focuses on patching.

### Tag Versioning

Since registry tags are immutable, re-patches use version-suffixed tags:

```
1.25.3-patched      ← initial patch
1.25.3-patched-1    ← first re-patch
1.25.3-patched-2    ← second re-patch
```

This works with custom tag templates too (e.g., `{{ .SourceTag }}-fixed` → `1.25.3-fixed`, `1.25.3-fixed-1`, etc.).

### Example Output

```
NAME               STATUS    SOURCE IMAGE            PATCHED TAG        DETAILS
nginx-test         Patched   registry/nginx:1.25.3   1.25.3-patched     OK
alpine-test        Skipped   registry/alpine:3.19    3.19-patched-2     no fixable vulnerabilities
ubuntu-test        Patched   registry/ubuntu:22.04   22.04-patched-3    OK
```

### Fail-Open Behavior

If Copa cannot determine whether to skip (e.g., report not found, parse errors, registry errors), it defaults to patching. This ensures scheduled jobs don't fail silently.

**Fail-open scenarios:**
- `-r` not provided → always patches
- Report file not found → proceeds with patching
- Report parsing fails → proceeds with patching, logs warning
- Registry tag listing fails → proceeds with patching

## Examples

### Nightly sweep with skip detection

Patch images and skip those with no new vulnerabilities:

```bash
# First time: patch all images
copa patch --config ./copa-bulk-config.yaml --push --timeout 20m

# Scan patched images (name files however you want)
trivy image registry.io/nginx:1.25.3-patched -f json -o reports/nginx.json
# ... scan other patched images ...

# Subsequent runs: skip images with clean reports
copa patch --config ./copa-bulk-config.yaml --push -r ./reports
```

On subsequent runs with reports, Copa automatically skips images that have no new vulnerabilities.

### Without skip detection

If you don't provide `-r`, Copa patches all images on every run:

```bash
copa patch --config ./copa-bulk-config.yaml --push --timeout 20m
```

### Keep base images fresh

Use `pattern` with `maxTags` to continuously patch the latest LTS tags. Example pattern for Ubuntu LTS: `^(20|22|24)\.04$`.

:::warning
Build attestations, signatures, and OCI referrers from the original images are not preserved or copied to the patched images.
:::
