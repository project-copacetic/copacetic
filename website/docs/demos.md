---
title: Demos
---

import AsciinemaPlayer from '@site/src/components/AsciinemaPlayer';

Copa can patch both OS-level and application-level vulnerabilities in container images. Each demo below walks through the same 5 steps:

1. **Scan** the image for vulnerabilities
2. **Export** scan results to JSON
3. **Create** a BuildKit instance
4. **Patch** the image with Copa
5. **Verify** the fix

:::info
App-level patching is an experimental feature. Prefix your `copa patch` command with `COPA_EXPERIMENTAL=1` to enable it.
:::

## 5 Steps to Patch a .NET Image

Patches a .NET runtime image with a known Newtonsoft.Json vulnerability (CVE-2024-21907), updating both OS packages and NuGet libraries using in-place DLL replacement.

```bash
# Step 1: Scan the image for vulnerabilities
trivy image --scanners vuln --pkg-types library --ignore-unfixed ashnam/dotnet-runtime-vuln:v2

# Step 2: Export scan results to JSON
trivy image --scanners vuln --pkg-types os,library --ignore-unfixed -f json -o dotnet-scan.json ashnam/dotnet-runtime-vuln:v2

# Step 3: Create a BuildKit instance
docker buildx create --name copademo-dotnet

# Step 4: Patch the image with Copa
COPA_EXPERIMENTAL=1 copa patch -i ashnam/dotnet-runtime-vuln:v2 \
    -r dotnet-scan.json -t v2-patched -a buildx://copademo-dotnet \
    --pkg-types os,library --library-patch-level major --ignore-errors --timeout 10m

# Step 5: Verify the fix
trivy image --scanners vuln --pkg-types library --ignore-unfixed ashnam/dotnet-runtime-vuln:v2-patched
```

<AsciinemaPlayer src="/casts/demo-dotnet.cast" rows={30} cols={120} />

## 5 Steps to Patch a Node.js Image

Patches a Ghost CMS image (Node.js-based), updating OS packages and npm dependencies via npm overrides.

```bash
# Step 1: Scan the image for vulnerabilities
trivy image --scanners vuln --pkg-types library --ignore-unfixed ghost:latest

# Step 2: Export scan results to JSON
trivy image --scanners vuln --pkg-types os,library --ignore-unfixed -f json -o nodejs-scan.json ghost:latest

# Step 3: Create a BuildKit instance
docker buildx create --name copademo-nodejs

# Step 4: Patch the image with Copa
COPA_EXPERIMENTAL=1 copa patch -i ghost:latest \
    -r nodejs-scan.json -t latest-patched -a buildx://copademo-nodejs \
    --pkg-types os,library --library-patch-level major --ignore-errors

# Step 5: Verify the fix
trivy image --scanners vuln --pkg-types library --ignore-unfixed ghost:latest-patched
```

<AsciinemaPlayer src="/casts/demo-nodejs.cast" rows={30} cols={120} />

## 5 Steps to Patch a Python Image

Patches a Python image, updating OS packages and pip dependencies.

```bash
# Step 1: Scan the image for vulnerabilities
trivy image --scanners vuln --pkg-types library --ignore-unfixed python:3.11.0

# Step 2: Export scan results to JSON
trivy image --scanners vuln --pkg-types os,library --ignore-unfixed -f json -o python-scan.json python:3.11.0

# Step 3: Create a BuildKit instance
docker buildx create --name copademo-python

# Step 4: Patch the image with Copa
COPA_EXPERIMENTAL=1 copa patch -i python:3.11.0 \
    -r python-scan.json -t 3.11.0-patched -a buildx://copademo-python \
    --pkg-types os,library --library-patch-level major --ignore-errors

# Step 5: Verify the fix
trivy image --scanners vuln --pkg-types library --ignore-unfixed python:3.11.0-patched
```

<AsciinemaPlayer src="/casts/demo-python.cast" rows={30} cols={120} />

## Running Demos Locally

The demo scripts are in the [`demo/`](https://github.com/project-copacetic/copacetic/tree/main/demo) directory. They use [demo-magic](https://github.com/paxtonhare/demo-magic) to simulate typing for recordings:

```bash
cd demo
bash copa-demo-python.sh
```

See the [demo README](https://github.com/project-copacetic/copacetic/blob/main/demo/README.md) for prerequisites and cleanup instructions.
