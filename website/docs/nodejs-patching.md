---
title: Node.js Package Patching
---

# Node.js Package Patching

Copa now supports patching Node.js package vulnerabilities in addition to OS-level vulnerabilities. This feature allows you to update vulnerable npm packages directly in container images without rebuilding.

## Overview

When scanning container images with Trivy using both OS and library vulnerability detection, Copa will now:

1. Detect Node.js package vulnerabilities from `package.json` and `package-lock.json` files
2. Apply security updates using `npm audit fix`
3. Create a new layer with the updated Node.js dependencies

## Prerequisites

- The container image must have Node.js and npm installed
- The image must contain `package.json` file(s) in standard locations
- Network access is required during patching to download updated packages

## Usage

### 1. Scan for both OS and Node.js vulnerabilities

```bash
export IMAGE=node:18-alpine
trivy image --vuln-type os,library --ignore-unfixed -f json -o report.json $IMAGE
```

### 2. Patch the image

Copa will automatically detect and patch both OS and Node.js vulnerabilities:

```bash
copa patch -r report.json -i $IMAGE
```

### 3. Verify the patches

```bash
trivy image --vuln-type os,library --ignore-unfixed $IMAGE-patched
```

## How It Works

Copa searches for `package.json` files in common Node.js application locations:
- `/app`
- `/usr/src/app`
- `/opt/app`
- `/src`
- `/workspace`
- Root directory `/`

For each location with a `package.json`, Copa will:
1. Run `npm audit fix --yes` to automatically update vulnerable packages
2. Fall back to direct package installation if audit fix fails
3. Clean the npm cache to minimize layer size

## Example

Here's an example of patching a Node.js application with vulnerable dependencies:

```bash
# Original image scan shows vulnerabilities
$ trivy image --vuln-type os,library node:18-alpine
...
app/package-lock.json (npm)
===========================
Total: 5 (UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 2, CRITICAL: 0)

┌─────────────────┬───────────────┬──────────┬──────────────────┬──────────────────┬─────────────────┐
│     Library     │ Vulnerability │ Severity │ Installed Version│  Fixed Version   │     Title       │
├─────────────────┼───────────────┼──────────┼──────────────────┼──────────────────┼─────────────────┤
│ ansi-regex      │ CVE-2021-3807 │ HIGH     │ 3.0.0            │ 3.0.1            │ Inefficient     │
│                 │               │          │                  │                  │ Regular         │
│                 │               │          │                  │                  │ Expression      │
├─────────────────┼───────────────┼──────────┼──────────────────┼──────────────────┼─────────────────┤
│ follow-redirects│ CVE-2022-0536 │ MEDIUM   │ 1.14.7           │ 1.14.8           │ Exposure of     │
│                 │               │          │                  │                  │ Sensitive       │
│                 │               │          │                  │                  │ Information     │
└─────────────────┴───────────────┴──────────┴──────────────────┴──────────────────┴─────────────────┘

# Patch with Copa
$ copa patch -r report.json -i node:18-alpine

# Verify patches were applied
$ trivy image --vuln-type os,library node:18-alpine-patched
...
app/package-lock.json (npm)
===========================
Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)
```

## Limitations

- Only npm-based Node.js projects are currently supported (not yarn or pnpm)
- The container must have npm installed and accessible
- Network access is required during patching
- Some vulnerabilities may require major version updates that `npm audit fix` won't perform automatically

## VEX Output

Patched Node.js packages are included in the VEX (Vulnerability Exploitability eXchange) document with a "node:" prefix to distinguish them from OS packages:

```json
{
  "statements": [
    {
      "vulnerability": {"name": "CVE-2021-3807"},
      "products": [
        {"@id": "pkg:npm/ansi-regex@3.0.1"}
      ],
      "status": "fixed"
    }
  ]
}
```