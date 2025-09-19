---
title: Copa Generate Command
---

The `copa generate` command enables you to leverage Docker's native build capabilities for patching container images. By producing a standard Docker build context, it allows you to use familiar `docker build` commands and options like `--platform`, `--push`, `--cache-from`, and `--output` that aren't available with `copa patch`. This integration with Docker's build system provides maximum flexibility for incorporating security patches into your existing container workflows.

## Overview

Instead of directly patching and pushing images like `copa patch`, the `generate` command produces a tar stream containing:

- A Dockerfile with instructions to apply the patch
- A patch layer directory with the security updates

This output can be piped directly to `docker build` or saved as a tar file for later use, giving you full control over the build process with all of Docker's advanced features.

## Key Advantages over `copa patch`

With `copa generate`, you can use any Docker build flag:

```bash
# Multi-platform builds
copa generate -i nginx:1.21.6 | docker buildx build --platform linux/amd64,linux/arm64 -t nginx:patched --push -

# Use build cache
copa generate -i nginx:1.21.6 | docker build --cache-from nginx:cache -t nginx:patched -

# Export to different formats
copa generate -i nginx:1.21.6 | docker build --output type=tar,dest=patched.tar -

# Set custom build arguments
copa generate -i nginx:1.21.6 | docker build --build-arg HTTP_PROXY=http://proxy:8080 -t nginx:patched -

# Specify target registry directly
copa generate -i nginx:1.21.6 | docker build -t myregistry.io/nginx:patched --push -
```

## Use Cases

The `copa generate` command is ideal for:

- **Docker Build Integration** - Use native Docker build flags and features not available in `copa patch`
- **Multi-platform Builds** - Leverage `docker buildx` for cross-platform patching
- **CI/CD Pipelines** - Integrate patches using standard Docker commands your team already knows
- **Build Cache Optimization** - Use Docker's layer caching mechanisms for faster builds
- **Air-gapped Environments** - Create patch contexts offline and apply them later
- **Custom Registries** - Push directly to any registry using Docker's native push capabilities

## Command Syntax

```bash
copa generate [flags]
```

### Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--image` | `-i` | Application image name and tag to patch **(required)** | |
| `--report` | `-r` | Vulnerability report file path (optional) | |
| `--tag` | `-t` | Tag for the patched image | |
| `--tag-suffix` | | Suffix for the patched image (if no explicit --tag provided) | `patched` |
| `--output-context` | | Path to save the generated tar context (instead of stdout) | stdout |
| `--scanner` | `-s` | Scanner that generated the report | `trivy` |
| `--addr` | `-a` | Address of buildkitd service | local docker daemon |
| `--working-folder` | `-w` | Working folder | system temp folder |
| `--timeout` | | Timeout for the operation | `5m` |
| `--ignore-errors` | | Ignore errors during patching | `false` |
| `--format` | `-f` | Output format for VEX document | `openvex` |
| `--output` | `-o` | Output file path for VEX document | |
| `--loader` | `-l` | Loader to use for loading images (`docker`, `podman`, or empty for auto-detection) | auto-detect |
| `--platform` | | Target platform(s) for multi-arch images (e.g., `linux/amd64,linux/arm64`). Valid platforms: `linux/amd64`, `linux/arm64`, `linux/riscv64`, `linux/ppc64le`, `linux/s390x`, `linux/386`, `linux/arm/v7`, `linux/arm/v6` | all platforms |
| `--cacert` | | Absolute path to buildkitd CA certificate | |
| `--cert` | | Absolute path to buildkit client certificate | |
| `--key` | | Absolute path to buildkit client key | |

## Basic Usage

### Pipe to Docker Build

The most common usage is piping the generated context directly to `docker build`:

```bash
# Generate and immediately build the patched image
copa generate -i nginx:1.21.6 | docker build -t nginx:1.21.6-patched -
```

### Save to File

Save the build context for later use:

```bash
# Generate and save the build context
copa generate -i nginx:1.21.6 --output-context patch-context.tar

# Later, build the patched image
docker build -t nginx:1.21.6-patched - < patch-context.tar
```

### With Vulnerability Report

Use a specific vulnerability report for targeted patching:

```bash
# First, generate a vulnerability report
trivy image --vuln-type os --ignore-unfixed -f json -o nginx-report.json nginx:1.21.6

# Generate patch context using the report
copa generate -i nginx:1.21.6 -r nginx-report.json | docker build -t nginx:1.21.6-patched -
```

## Build Context Structure

The generated tar file contains:

```text
├── Dockerfile              # Instructions to apply the patch
└── patch/                  # Directory with updated packages
    ├── usr/
    ├── lib/
    └── ...                 # Other patched files
```

### Generated Dockerfile

The Dockerfile in the build context looks like:

```dockerfile
FROM nginx:1.21.6
COPY patch/ /
LABEL sh.copa.image.patched="2024-03-20T10:30:00Z"
```

## Comparison with `copa patch`

| Feature | `copa patch` | `copa generate` |
|---------|--------------|-----------------|
| **Output** | Patched image in registry/daemon | Build context tar stream |
| **Registry Access** | Required for push | Not required |
| **Use Case** | Direct patching | Pipeline integration |
| **Flexibility** | Less flexible | Highly flexible |
| **Performance** | Single operation | Can be parallelized |

## Best Practices

### 1. Always Verify Output

When using stdout, ensure the output is valid before piping:

```bash
# Verify the context first
copa generate -i nginx:1.21.6 --output-context test.tar
tar -tf test.tar  # Check contents

# Then use in production
copa generate -i nginx:1.21.6 | docker build -t nginx:patched -
```

### 2. Handle TTY Detection

Copa refuses to write tar data to a terminal. Always redirect output:

```bash
# ❌ Wrong - outputs to terminal
copa generate -i nginx:1.21.6

# ✅ Correct - redirect to file or pipe
copa generate -i nginx:1.21.6 > patch.tar
copa generate -i nginx:1.21.6 | docker build -t nginx:patched -
```

### 3. Use Specific Reports for Reproducibility

For consistent results across environments:

```bash
# Generate report once
trivy image --vuln-type os -f json -o report.json nginx:1.21.6

# Use the same report for all patch generations
copa generate -i nginx:1.21.6 -r report.json --output-context patch.tar
```

### 4. Optimize for CI/CD

Cache generated contexts when possible:

```bash
# Generate context with cache key
CACHE_KEY=$(sha256sum report.json | cut -d' ' -f1)
CACHE_FILE="patch-cache/${CACHE_KEY}.tar"

if [ ! -f "$CACHE_FILE" ]; then
  copa generate -i nginx:1.21.6 -r report.json --output-context "$CACHE_FILE"
fi

docker build -t nginx:patched - < "$CACHE_FILE"
```

## Troubleshooting

### "No local sources enabled" Error

This error from `docker build` indicates an invalid or empty build context:

```bash
# Check if copa generate succeeded
copa generate -i nginx:1.21.6 --output-context test.tar || echo "Generation failed"

# Verify tar contents
tar -tf test.tar
```

### Empty Patch Layer

If the image has no upgradable packages, Copa will log a message and generate a minimal patch layer:

```bash
# Copa will log when an image is already up-to-date
copa generate -i alpine:latest --output-context patch.tar
# Output: INFO[0005] Image is already up-to-date. No packages to upgrade.

# The generated tar will contain a minimal Dockerfile with no actual patches
# You can still use it with docker build, but no changes will be applied
```

### BuildKit Connection Issues

If BuildKit isn't detected automatically, specify the address:

```bash
# Use Docker's BuildKit
copa generate -i nginx:1.21.6 --addr docker://

# Use a specific buildx builder
docker buildx create --name copa-builder --use
copa generate -i nginx:1.21.6 --addr buildx://copa-builder
```

## Summary

The `copa generate` command provides a flexible way to integrate Copa's patching capabilities into any container build workflow. By producing standard Docker build contexts, it enables:

- Seamless CI/CD integration
- Offline patching workflows
- Custom build pipelines
- Parallel processing of multiple images

Whether you're automating security updates in production or integrating patches into complex build systems, `copa generate` offers the flexibility and control needed for enterprise container security.

## Next Steps

- Learn about [scanner plugins](./scanner-plugins.md) for custom vulnerability sources
- Explore [best practices](./best-practices.md) for production use
- Check out the [quick start guide](./quick-start.md) for basic Copa usage
- Read about [multi-platform patching](./multiplatform-patching.md) for complex images
