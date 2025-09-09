---
title: BuildKit Frontend
---

Copa can be used as a [BuildKit frontend](https://docs.docker.com/build/buildkit/frontend/) to patch container images directly within BuildKit builds. This approach offers better integration with CI/CD pipelines and containerized workflows compared to the traditional CLI approach.

## Overview

The Copa BuildKit frontend leverages BuildKit's [gateway interface](https://github.com/moby/buildkit?tab=readme-ov-file#exploring-dockerfiles) to provide container vulnerability patching as a native BuildKit operation. This enables:

- **Containerized Patching**: No need to install Copa CLI on build machines
- **Build Context Integration**: Direct access to vulnerability reports and build artifacts
- **CI/CD Optimized**: Seamless integration with Docker Buildx, GitHub Actions, and other BuildKit-based tools
- **Progress Tracking**: Native BuildKit progress reporting during patch operations
- **Multi-platform Support**: Automatic handling of multi-architecture images

## Prerequisites

Before using the Copa BuildKit frontend, ensure you have:

- **BuildKit Instance**: Access to BuildKit via:
  - `buildctl` CLI tool; or
  - Docker Buildx (`docker buildx build`); or
  - BuildKit daemon running locally
- **Copa Frontend Image**: Available at `ghcr.io/project-copacetic/copacetic-frontend:latest`
- **Vulnerability Scanner**: Trivy or another supported scanner for generating reports
- **Container Runtime**: Docker or Podman for image operations

## Basic Usage

### Docker Buildx (Recommended)

Docker Buildx provides the most seamless integration with existing Docker workflows:

```bash
# Generate vulnerability report
trivy image --format json --output report.json nginx:1.21.6

# Create build context directory with reports
mkdir build-context
cp report.json build-context/

# Create empty Dockerfile (required for buildx)
touch build-context/Dockerfile

# Set up buildx builder
docker buildx create --name copa-builder --use

# Patch using buildx
docker buildx build \
  --build-arg BUILDKIT_SYNTAX=ghcr.io/project-copacetic/copacetic-frontend:latest \
  --build-arg image=nginx:1.21.6 \
  --build-arg report=report.json \
  --build-context report=./build-context \
  --output type=image,name=nginx:1.21.6-patched \
  ./build-context
```

:::info Docker Buildx Requirements
Docker Buildx requires a `Dockerfile` in the build context, even if it's empty. The vulnerability reports can be placed in the same context directory.
:::

### BuildKit CLI Alternative

For environments without Docker Buildx, use the `buildctl` CLI directly:

```bash
# Generate vulnerability report (same as above)
trivy image --format json --output report.json nginx:1.21.6

# Create report context directory
mkdir reports
cp report.json reports/

# Patch using buildctl
buildctl build \
  --frontend=gateway.v0 \
  --opt source=ghcr.io/project-copacetic/copacetic-frontend:latest \
  --opt image=nginx:1.21.6 \
  --opt report=report.json \
  --opt scanner=trivy \
  --local report=./reports \
  --opt context:report=local:report \
  --output type=image,name=nginx:1.21.6-patched
```

## Configuration Options

The Copa BuildKit frontend accepts the following options via `--build-arg` (or `--opt` in `buildctl`) flags:

### Required Options

| Option  | Description                   | Example        |
| ------- | ----------------------------- | -------------- |
| `image` | Base container image to patch | `nginx:1.21.6` |

### Report Options

| Option    | Description                                 | Default | Example                                |
| --------- | ------------------------------------------- | ------- | -------------------------------------- |
| `report`  | Path to vulnerability report within context | -       | `report.json` or `.` (for directories) |
| `scanner` | Vulnerability scanner type                  | `trivy` | `trivy`, `grype`                       |

### Platform Options

| Option     | Description                         | Default     | Example                   |
| ---------- | ----------------------------------- | ----------- | ------------------------- |
| `platform` | Target platform(s), comma-separated | Auto-detect | `linux/amd64,linux/arm64` |

### Output Options

| Option   | Description                  | Default | Example           |
| -------- | ---------------------------- | ------- | ----------------- |
| `tag`    | Custom tag for output image  | -       | `v1.0.0-patched`  |
| `suffix` | Suffix for output image name | -       | `-copa-patched`   |
| `output` | VEX document output path     | -       | `vex.json`        |
| `format` | VEX document format          | -       | `openvex`, `csaf` |

### Behavior Options

| Option          | Description                              | Default | Example |
| --------------- | ---------------------------------------- | ------- | ------- |
| `ignore-errors` | Continue patching on non-critical errors | `false` | `true`  |

## Context Handling

The Copa frontend uses BuildKit's context system to access vulnerability reports and other build artifacts.

### Single Report File

For single-platform patching with one vulnerability report:

```bash
# Directory structure
reports/
└── report.json

# Command
buildctl build \
  --opt report=report.json \
  --local report=./reports \
  --opt context:report=local:report \
  # ... other options
```

### Multi-platform Directory

For multi-platform patching with platform-specific reports:

```bash
# Directory structure
reports/
├── linux-amd64.json
├── linux-arm64.json
└── linux-arm-v7.json

# Command
buildctl build \
  --opt report=. \
  --opt platform=linux/amd64,linux/arm64,linux/arm/v7 \
  --local report=./reports \
  --opt context:report=local:report \
  # ... other options
```

:::note Platform Naming
Platform-specific reports do not need to follow any specific naming pattern as long as they are correctly referenced in the `report` option. However, using a consistent naming convention (e.g., `linux-amd64.json` for `linux/amd64`) can help avoid confusion.
:::

## Advanced Examples

### Multi-platform Patching

Patch a multi-architecture image with platform-specific vulnerability reports:

```bash
# Generate reports for each platform
trivy image --platform linux/amd64 --format json --output linux-amd64.json nginx:1.21.6
trivy image --platform linux/arm64 --format json --output linux-arm64.json nginx:1.21.6

# Organize reports
mkdir reports
mv linux-*.json reports/

# Patch all platforms
buildctl build \
  --frontend=gateway.v0 \
  --opt source=ghcr.io/project-copacetic/copacetic-frontend:latest \
  --opt image=nginx:1.21.6 \
  --opt report=. \
  --opt scanner=trivy \
  --opt platform=linux/amd64,linux/arm64 \
  --local report=./reports \
  --opt context:report=local:report \
  --output type=image,name=nginx:1.21.6-multiarch-patched
```

### CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: Patch Container Images
on: [push]

jobs:
  patch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Install Trivy
        run: |
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

      - name: Generate vulnerability report
        run: |
          mkdir build-context
          trivy image --format json --output build-context/report.json nginx:1.21.6
          touch build-context/Dockerfile

      - name: Patch image with Copa frontend
        run: |
          docker buildx build \
            --build-arg BUILDKIT_SYNTAX=ghcr.io/project-copacetic/copacetic-frontend:latest \
            --build-arg image=nginx:1.21.6 \
            --build-arg report=report.json \
            --build-context report=./build-context \
            --output type=image,name=nginx:1.21.6-patched,push=true \
            ./build-context
```

### Custom BuildKit Address

Use with a specific BuildKit daemon:

```bash
# Connect to remote BuildKit
buildctl --addr tcp://buildkit-server:1234 build \
  --frontend=gateway.v0 \
  --opt source=ghcr.io/project-copacetic/copacetic-frontend:latest \
  --opt image=nginx:1.21.6 \
  --opt report=report.json \
  --local report=./reports \
  --opt context:report=local:report \
  --output type=image,name=nginx:1.21.6-patched
```

## Frontend vs CLI Comparison

| Aspect                 | BuildKit Frontend                      | Copa CLI                           |
| ---------------------- | -------------------------------------- | ---------------------------------- |
| **Installation**       | No local installation required         | Requires Copa binary installation  |
| **Context Handling**   | Native BuildKit context support        | Manual file management             |
| **CI/CD Integration**  | Seamless with BuildKit-based workflows | Requires container or binary setup |
| **Progress Tracking**  | Native BuildKit progress reporting     | CLI output only                    |
| **Caching**            | Leverages BuildKit's caching layers    | Limited caching support            |
| **Multi-platform**     | Automatic platform detection           | Manual platform handling           |
| **Resource Isolation** | Runs in isolated BuildKit containers   | Uses local system resources        |

### When to Use Each Approach

**Use BuildKit Frontend when:**

- Integrating with CI/CD pipelines
- Building containerized applications
- Working with multi-platform images
- Want native BuildKit progress and caching
- Prefer not installing additional CLI tools

**Use Copa CLI when:**

- Interactive development and debugging
- Simple one-off patching tasks
- Need fine-grained control over the process
- Working outside containerized environments

## Troubleshooting

### Common Issues

**Frontend image not found:**

```bash
# Error: failed to resolve frontend image
# Solution: Verify frontend image reference
# For Docker Buildx:
--build-arg BUILDKIT_SYNTAX=ghcr.io/project-copacetic/copacetic-frontend:latest
# For buildctl:
--opt source=ghcr.io/project-copacetic/copacetic-frontend:latest
```

**Context not found:**

```bash
# Error: failed to read report from context
# Solution: Ensure report context is properly mounted
# For Docker Buildx:
--build-arg report=report.json \
--build-context report=./build-context
# For buildctl:
--local report=./reports \
--opt context:report=local:report
```

**Platform mismatch:**

```bash
# Error: no report found for platform
# Solution: Check platform-specific report file naming
# Expected: linux-amd64.json for linux/amd64 platform
```

**BuildKit connection issues:**

```bash
# Error: failed to dial buildkit daemon
# Solution: Check BuildKit daemon status
docker ps | grep buildkitd
# or
buildctl debug workers
```

## Next Steps

- Learn about [Multi-Platform Patching](multiplatform-patching.md) strategies
- Explore [Custom BuildKit Addresses](custom-address.md) for advanced setups
- Check out the [Copa GitHub Action](github-action.md) for automated workflows
- Review [Output Formats](output.md) for VEX document generation

:::tip
The BuildKit frontend automatically inherits your BuildKit configuration, including registry authentication, network settings, and caching policies. No additional setup is required for most environments.
:::
