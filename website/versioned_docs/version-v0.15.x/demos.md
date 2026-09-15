---
title: Demos
---

import AsciinemaPlayer from '@site/src/components/AsciinemaPlayer';

Copa can patch both OS-level and application-level vulnerabilities in container images. Each demo below walks through the same steps:

1. **Scan** the image for vulnerabilities
2. **Export** scan results to JSON
3. **Create** a BuildKit instance (or use `docker://` for local images)
4. **Patch** the image with Copa
5. **Verify** the fix

:::info
App-level patching is an experimental feature. Prefix your `copa patch` command with `COPA_EXPERIMENTAL=1` to enable it.
:::

## Patch a Locally-Built .NET Image

Builds the [Azure Relay Bridge](https://github.com/Azure/azure-relay-bridge) .NET image locally and patches it, updating both OS packages and NuGet libraries using in-place DLL replacement. Uses `docker://` to access the local image directly via Docker's built-in BuildKit.

```bash
# Step 0: Build the .NET image locally
git clone --depth 1 https://github.com/Azure/azure-relay-bridge.git /tmp/azure-relay-bridge
docker build -t azure-relay-bridge:local /tmp/azure-relay-bridge

# Step 1: Scan the image for vulnerabilities
trivy image --scanners vuln --pkg-types library --ignore-unfixed azure-relay-bridge:local

# Step 2: Export scan results to JSON
trivy image --scanners vuln --pkg-types os,library --ignore-unfixed -f json -o dotnet-scan.json azure-relay-bridge:local

# Step 3: Patch the image with Copa (using docker:// for local images)
COPA_EXPERIMENTAL=1 copa patch -i azure-relay-bridge:local \
    -r dotnet-scan.json -t local-patched -a docker:// \
    --pkg-types os,library --library-patch-level major --ignore-errors --timeout 30m

# Step 4: Verify the fix
trivy image --scanners vuln --pkg-types library --ignore-unfixed azure-relay-bridge:local-patched
```

<AsciinemaPlayer src="/casts/demo-dotnet.cast" rows={30} cols={120} />

## 5 Steps to Patch a Python Image

Patches a Python 3.11 Alpine image, updating OS packages and pip dependencies.

```bash
# Step 1: Scan the image for vulnerabilities
trivy image --scanners vuln --pkg-types library --ignore-unfixed python:3.11-alpine

# Step 2: Export scan results to JSON
trivy image --scanners vuln --pkg-types os,library --ignore-unfixed -f json -o python-scan.json python:3.11-alpine

# Step 3: Create a BuildKit instance
docker buildx create --name copademo-python

# Step 4: Patch the image with Copa
COPA_EXPERIMENTAL=1 copa patch -i python:3.11-alpine \
    -r python-scan.json -t 3.11-alpine-patched -a buildx://copademo-python \
    --pkg-types os,library --library-patch-level major --ignore-errors --timeout 20m

# Step 5: Verify the fix
trivy image --scanners vuln --pkg-types library --ignore-unfixed python:3.11-alpine-patched
```

<AsciinemaPlayer src="/casts/demo-python.cast" rows={30} cols={120} />

## Running Demos Locally

The demo scripts are in the [`demo/`](https://github.com/project-copacetic/copacetic/tree/main/demo) directory. They use [demo-magic](https://github.com/paxtonhare/demo-magic) to simulate typing for recordings:

```bash
cd demo
bash copa-demo-python.sh
```

See the [demo README](https://github.com/project-copacetic/copacetic/blob/main/demo/README.md) for prerequisites and cleanup instructions.
