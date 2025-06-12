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

Copa searches for **Node.js application roots** - directories that contain both `package.json` AND `package-lock.json` files. It specifically excludes any paths within `node_modules` directories to avoid corrupting the dependency tree.

### Application Root Detection

Copa searches in this order:
1. **Common application locations** (preferred):
   - `/app`
   - `/usr/src/app`
   - `/opt/app`
   - `/workspace`
   - Root directory `/`

2. **Broader search** (if no common locations found):
   - Searches the entire filesystem for `package.json` files
   - Filters out any within `node_modules` directories
   - Only includes directories that also have `package-lock.json`

### Why Both Files Are Required

- **`package.json`**: Defines the application's dependencies
- **`package-lock.json`**: Locks specific versions and ensures reproducible installs
- **Together**: Indicate this is an application root, not just a package within `node_modules`

Note: Copa will not patch individual packages inside `node_modules` directories. Each package in `node_modules` has its own `package.json` but lacks `package-lock.json`, and patching them individually would corrupt the dependency tree.

For each detected Node.js application root, Copa will:
1. **Pre-validate packages** - Check for problematic version patterns (pre-release, multiple versions)
2. **Use targeted updates** - Install specific package versions rather than using `npm audit fix --force`
3. **Handle direct vs transitive dependencies** - Update direct dependencies with exact versions, use `npm update` for transitive ones
4. **Update lock files** - Ensure `package-lock.json` remains consistent after updates
5. **Clean the npm cache** to minimize layer size

### Update Strategy

Copa uses a conservative update approach to avoid breaking applications:
- **Direct dependencies**: Updated with `npm install package@version --save-exact`
- **Transitive dependencies**: Updated with `npm update package`
- **Multiple fixed versions**: Uses the first version from comma-separated lists
- **Pre-release versions**: Issues warnings but attempts update anyway

## Example

Here's an example of patching a Node.js application with vulnerable dependencies using the Bitnami Express.js image:

```bash
# Scan the Bitnami Express image for vulnerabilities
$ trivy image --vuln-type os,library --ignore-unfixed -f json -o report.json bitnami/express:latest

# Example scan output showing vulnerable packages in /opt/bitnami/express
...
opt/bitnami/express/package.json (npm)
======================================
Total: 4 (UNKNOWN: 0, LOW: 0, MEDIUM: 2, HIGH: 1, CRITICAL: 1)

┌─────────────────┬───────────────┬──────────┬──────────────────┬──────────────────┬─────────────────┐
│     Library     │ Vulnerability │ Severity │ Installed Version│  Fixed Version   │     Title       │
├─────────────────┼───────────────┼──────────┼──────────────────┼──────────────────┼─────────────────┤
│ express         │ CVE-2024-10491│ CRITICAL │ 0.0.0            │ >=4.19.2 <5,     │ Express.js      │
│                 │               │          │                  │ >=5.0.0-alpha.1  │ Cross-site      │
│                 │               │          │                  │                  │ Scripting       │
├─────────────────┼───────────────┼──────────┼──────────────────┼──────────────────┼─────────────────┤
│ express         │ CVE-2014-6393 │ HIGH     │ 0.0.0            │ >=3.11 <4,       │ Express.js      │
│                 │               │          │                  │ >=4.5            │ Security Bypass │
└─────────────────┴───────────────┴──────────┴──────────────────┴──────────────────┴─────────────────┘

# Patch with Copa
$ copa patch -r report.json -i bitnami/express:latest

# Copa output shows the patching process
time="..." level=info msg="Found Node.js vulnerabilities in Node.js"
time="..." level=info msg="Found 1 OS package updates and 125 Node.js package updates"
time="..." level=info msg="Found Node.js app root: /opt/bitnami/express"
time="..." level=info msg="Processing 125 Node.js package updates"
time="..." level=info msg="Successfully applied 125 Node.js package updates"

# Verify patches were applied
$ trivy image --vuln-type os,library bitnami/express:latest-patched
...
opt/bitnami/express/package.json (npm)
======================================
Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)
```

## Limitations

### Current Implementation
- **Package Manager Support**: Only npm is supported (not yarn, pnpm, or other package managers)
- **Lock File Requirement**: Both `package.json` and `package-lock.json` must be present together
- **Directory Detection**: Limited to predefined common locations
- **Registry Support**: Only default npm registry (no private registries or authentication)

### Known Edge Cases
- **Non-existent fixed versions**: Security advisories may recommend versions that were never published or were unpublished
- **Dependency conflicts**: Updates may fail due to peer dependency conflicts or version constraints
- **Native modules**: Packages with native bindings may require recompilation after Node.js version changes
- **Multiple package managers**: Applications using yarn.lock or pnpm-lock.yaml files won't be processed
- **Breaking changes**: No protection against major version updates that introduce breaking changes

### Best Practices
- **Test thoroughly** after patching, as Copa doesn't validate application functionality
- **Review warnings** in Copa logs about problematic version patterns
- **Use `--ignore-errors`** cautiously, as failed updates might leave applications in inconsistent states
- **Consider manual updates** for complex applications with strict version requirements

## Troubleshooting

### No packages updated
If no packages are updated:
1. Ensure `COPA_EXPERIMENTAL=1` is set
2. Check that vulnerabilities are in npm packages (not just OS packages)
3. Verify `package.json` and `package-lock.json` exist together in the same directory
4. Ensure the Node.js application is not located inside a `node_modules` directory
5. Check Copa logs for directory detection messages like "Found Node.js app root: /path"

### "No Node.js application roots found" warning
If Copa shows this warning:
1. **Missing lock file**: Ensure `package-lock.json` exists alongside `package.json`
2. **Wrong location**: Move your application to a standard location like `/app`
3. **Inside node_modules**: The application may be incorrectly placed within a `node_modules` directory
4. **Generate lock file**: Run `npm install` to create `package-lock.json` if missing

### Package not found errors
If Copa reports warnings about packages not being updated:
1. Check if the package name includes special characters (e.g., `@babel/core`)
2. Verify the fixed version exists in npm registry
3. Ensure you're not trying to patch packages inside `node_modules`

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