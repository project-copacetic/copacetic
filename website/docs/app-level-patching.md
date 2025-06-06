---
title: App-Level Patching
---

:::warning Experimental Feature
App-level patching is an experimental feature that requires setting the `COPA_EXPERIMENTAL=1` environment variable to enable. This feature is under active development, and future releases may introduce breaking changes. Feedback is welcome!
:::

Copa supports patching application-level dependencies, such as Python packages, in addition to operating system packages. This feature allows you to update vulnerable libraries and packages in various programming language ecosystems.

## Overview

App-level patching works by scanning and updating application dependencies found in your container images. Unlike OS-level patching which updates system packages, app-level patching focuses on:

- Python packages (`pip` is the supported package manager)

Please note that app-level patching requires scanner results that identify vulnerabilities in application libraries.

## Package Type Filtering

Copa supports filtering between different types of packages using the `--pkg-types` flag:

```bash
# Patch only OS packages
copa patch -i $IMAGE --pkg-types os ...

# Patch only library/app-level packages
copa patch -i $IMAGE --pkg-types library ...

# Patch both OS and library packages (default)
copa patch -i $IMAGE --pkg-types os,library ...
```

### Package Type Options

- `os`: Operating system packages (APT, YUM, APK, etc.). This is the default behavior if no `--pkg-types` flag is specified.
- `library`: Application-level packages (Python, Node.js, etc.)
- `os,library`: Both types

This filtering is particularly useful when you want to:

- Apply different patch policies to OS vs. application dependencies
- Separate OS security updates from application updates
- Reduce the scope of changes in production environments

## Patch Level Control

Copa allows you to control how aggressively application-level packages are updated based on their versioning. This is particularly useful for managing compatibility and stability in your applications. The `--library-patch-level` flag determines the maximum version bump allowed for library updates:

```bash
# Only apply patch-level updates (e.g., 2.6.0 → 2.6.1)
copa patch -i $IMAGE --pkg-types library --library-patch-level patch ...

# Allow minor version updates (e.g., 2.6.0 → 2.7.0, prefer 2.6.1)
copa patch -i $IMAGE --pkg-types library --library-patch-level minor ...

# Allow major version updates (e.g., 2.6.0 → 3.0.0, prefer 2.6.1)
copa patch -i $IMAGE --pkg-types library --library-patch-level major ...
```

Please note that the `--library-patch-level` flag requires the `--pkg-types library` option to be set. Default behavior is `patch` level if not specified.

### Patch Level Behavior

The patch level determines the maximum version bump allowed for library updates:

#### `patch` Level (Recommended)

- **Allows**: `2.6.0` → `2.6.1`, `2.6.2`, etc.
- **Blocks**: `2.6.0` → `2.7.0` or `3.0.0`
- **Use case**: Conservative updates, minimal risk of breaking changes

#### `minor` Level

- **Allows**: `2.6.0` → `2.6.1` (preferred) or `2.7.0`
- **Blocks**: `2.6.0` → `3.0.0`
- **Preference**: Patch versions are preferred over minor versions
- **Use case**: Moderate updates, some new features acceptable

#### `major` Level

- **Allows**: Any version update
- **Preference**: Patch > Minor > Major (safest compatible version)
- **Use case**: Aggressive updates, all fixes applied regardless of compatibility risk

:::warning
Please note that `copa` does not guarantee compatibility with all versions. The patch level only controls the maximum version bump allowed. Always test your application after patching.
:::

### Special Package Handling

Some packages have special handling due to their nature:

- **certifi**: Always updated to the latest version regardless of patch level setting

## Usage Examples

```bash
export COPA_EXPERIMENTAL=1
export IMAGE=python:3.11.0

# Scan for Python package vulnerabilities
trivy image --vuln-type os,library --ignore-unfixed -f json -o python-scan.json $IMAGE

# Apply conservative Python package updates
copa patch \
    -i $IMAGE \
    -r python-scan.json \
    --pkg-types os,library \
    --library-patch-level patch
```
