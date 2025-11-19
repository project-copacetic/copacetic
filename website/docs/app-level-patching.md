---
title: App-Level Patching
---

:::warning Experimental Feature
App-level patching is an experimental feature that requires setting the `COPA_EXPERIMENTAL=1` environment variable to enable. This feature is under active development, and future releases may introduce breaking changes. Feedback is welcome!
:::

Copa supports patching application-level dependencies, such as Python packages, Node.js packages, and Go modules, in addition to operating system packages. This feature allows you to update vulnerable libraries and packages in various programming language ecosystems.

## Overview

App-level patching works by scanning and updating application dependencies found in your container images. Unlike OS-level patching which updates system packages, app-level patching focuses on:

- Python packages (`pip` is the supported package manager)
- Node.js packages (`npm` is the supported package manager, for both user applications and globally-installed packages)
- Go modules (`go.mod` files are supported; vendor directories are also supported)

Please note that app-level patching requires scanner results that identify vulnerabilities in application libraries.

## Package Type Filtering

Copa supports filtering between different types of packages using the `--pkg-types` flag:

```bash
# Patch only OS packages (default)
copa patch -i $IMAGE --pkg-types os ...

# Patch only library/app-level packages
copa patch -i $IMAGE --pkg-types library ...

# Patch both OS and library packages
copa patch -i $IMAGE --pkg-types os,library ...
```

### Package Type Options

- `os`: Operating system packages (APT, YUM, APK, etc.). This is the default behavior if no `--pkg-types` flag is specified.
- `library`: Application-level packages (Python, Node.js, Go, etc.)
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
- **Preference**: If both `2.6.1` and `2.7.0` are available, it will choose `2.6.1` (patch) over `2.7.0` (minor)
- **Use case**: Moderate updates, some new features acceptable

#### `major` Level

- **Allows**: Any version update
- **Preference**: When comma-separated versions are available, prefers Patch > Minor > Major for compatibility. When no comma-separated versions exist, picks the highest version to fix all CVEs.
- **Example**: If both `2.6.1` and `2.7.0` are available, it will choose `2.6.1` for better compatibility
- **Use case**: Aggressive updates, all fixes applied regardless of compatibility risk

:::warning
Please note that `copa` does not guarantee compatibility with all versions. The patch level only controls the maximum version bump allowed. Always test your application after patching.
:::

### Special Package Handling

Some packages have special handling due to their nature:

- **certifi**: Always updated to the latest version regardless of patch level setting

## Usage Examples

To use app-level patching, you need to have a scanner result file that contains vulnerabilities for application-level packages. Below is an example of how to scan a Python image and then apply patches using Copa.

```bash
export COPA_EXPERIMENTAL=1
export IMAGE=python:3.11.0

# Scan for Python package vulnerabilities
trivy image --vuln-type os,library --ignore-unfixed -f json -o python-scan.json $IMAGE
```

### Basic Usage

```bash
# Apply patch-level Python package updates only
copa patch \
    -i $IMAGE \
    -r python-scan.json \
    --pkg-types os,library \
    --library-patch-level patch
```

### Ignoring Errors

Sometimes, certain packages may not be compatible with the patching process or may not have available updates. In such cases, you can use the `--ignore-errors` flag to allow Copa to continue patching other packages even if some fail. This is useful in environments where you want to apply as many updates as possible without failing the entire patching process.

```bash
# Apply patch-level Python package updates, ignoring errors
copa patch \
    -i $IMAGE \
    -r python-scan.json \
    --pkg-types os,library \
    --library-patch-level major \
    --ignore-errors
```

## Limitations

Due to the nature of app-level patching, it may not be as comprehensive as OS-level patching. Some known limitations are:

### Python

#### Dependency Resolution

Copa does not perform dependency resolution for application-level packages. It applies updates based on the scanner results without checking for compatibility with other packages in the environment. This means that while Copa can update vulnerable packages, it may not resolve all dependency conflicts that arise from those updates.

For example, if a package has a strict version requirement that conflicts with the updated version, you may encounter errors like:

```shell
#8 8.971 ERROR: Cannot install azure-cli and paramiko==3.4.0 because these package versions have conflicting dependencies.
#8 8.971
#8 8.971 The conflict is caused by:
#8 8.971     The user requested paramiko==3.4.0
#8 8.971     azure-cli-core 2.40.0 depends on paramiko<3.0.0 and >=2.0.8
#8 8.971
#8 8.971 To fix this you could try to:
#8 8.971 1. loosen the range of package versions you've specified
#8 8.971 2. remove package versions to allow pip attempt to solve the dependency conflict
```

#### Python Version Compatibility

Copa does not check whether the updated Python packages are compatible with the Python version in the image. For example, if you update a package that requires Python 3.12 to a version that is not compatible with Python 3.11, you may encounter runtime or dependency resolution errors.

#### Testing and Validation

Due to the nature of app-level patching, it is _highly recommended_ to thoroughly test your application after applying updates. Copa does not perform any automated testing or validation of the patched application, so you should ensure that your application functions correctly with the updated dependencies.

#### Non Existent Versions

Trivy provides vulnerability data for Python dependencies using [GitHub Security Advisories](https://github.com/advisories) (GHSA). However, it does not check whether the patched version exists in the [Python Package Index](https://pypi.org) (PyPI). For example, [`GHSA-3749-ghw9-m3mg`](https://github.com/advisories/GHSA-3749-ghw9-m3mg) contains a vulnerability for torch package, but the patched version `2.0.2.7.1-rc1` does not exist in PyPI at the time of this writing.

#### Virtual Environment and Package Manager Support

Currently, only Python packages managed by `pip` are supported. We have not evaluated or implemented support for virtual environments, or other Python package managers like `conda` or `poetry` and others. This might break compatibility with applications that use these package managers.

#### Replacing PyPI

Copa does not support replacing the default [Python Package Index](https://pypi.org) (PyPI) with a custom index or mirror at this time. This means that all package updates are fetched from the official PyPI repository, which may not be suitable for all environments, especially those with strict network policies or private package registries.

### Node.js

Copa supports patching Node.js applications and globally-installed npm packages. When scanning an image for vulnerabilities, Copa will:

1. **User Applications**: Detect and patch packages defined in `package.json` files.
2. **Global Packages**: Detect and patch globally-installed npm packages (e.g., `eslint`, `typescript`, etc.).

#### Usage Example

```bash
export COPA_EXPERIMENTAL=1
export IMAGE=node:18

# Scan for Node.js package vulnerabilities
trivy image --vuln-type os,library --ignore-unfixed -f json -o nodejs-scan.json $IMAGE

# Apply patch-level Node.js package updates
copa patch \
    -i $IMAGE \
    -r nodejs-scan.json \
    --pkg-types os,library \
    --library-patch-level patch
```

#### Node.js Limitations

##### Node.js Dependency Resolution

Like Python, Copa does not perform full dependency resolution. It applies updates based on scanner results without checking for compatibility conflicts.

More importantly, the `npm overrides` strategy is only capable of patching **transitive dependencies** (dependencies of your dependencies). It **cannot** patch a package that is listed as a **direct dependency** in your application's `package.json`. Attempting to do so will result in an `EOVERRIDE` error from `npm`, and the patch for that package will be skipped.

##### Patching Core Tooling (npm, corepack)

Attempting to patch the `npm` package manager itself is an unsupported edge case. The `npm` project has internal dependencies that are not available on the public registry, which causes the `npm install` process to fail. To ensure stability and prevent hangs, Copa's patching logic is configured to automatically **skip patching `npm` and `corepack`** when they are detected as globally-installed packages.

##### Node.js Package Manager Support

Currently, only `npm` is supported. Other Node.js package managers like `yarn` or `pnpm` are not supported at this time.

##### Incompatible Project Setups

The patching process is designed for standard `npm`-based projects. Images built with other package managers or non-standard project structures will likely fail to patch. Known incompatibilities include:

- **Projects using `yarn` or `pnpm`:** These package managers have different dependency resolution mechanisms and file structures (e.g., `yarn.lock`, `.pnp.cjs`).
- **Projects using `patch:` protocol:** Some projects apply custom patches to their dependencies using a `patch:` directive. The `npm` version in most containers does not support this protocol, causing an `EUNSUPPORTEDPROTOCOL` error.
- **Non-standard project structures:** Some frameworks, like Meteor, bundle dependencies in a way that doesn't follow the standard single `package.json` at the project root. This can confuse the application detection logic.

##### Node.js Native Modules

Copa uses the `--ignore-scripts` flag when installing Node.js packages to avoid issues with native module compilation (node-gyp). This means:

- Packages with native dependencies may not build their native components.
- Most security patches work without native rebuilds.
- In rare cases, functionality relying on native modules might be affected.

##### Node.js Testing and Validation

As with Python packages, it is *highly recommended* to thoroughly test your Node.js application after applying updates. Copa does not perform automated testing or validation of the patched application.

### Go

Copa supports patching Go module dependencies defined in `go.mod` files. When scanning an image for vulnerabilities, Copa will:

1. **Go Modules**: Detect and patch module dependencies defined in `go.mod` files
2. **Workspaces**: Support Go 1.18+ multi-module workspaces (`go.work` files)
3. **Vendor Directories**: Automatically update `vendor/` directories when present

#### Usage Example

```bash
export COPA_EXPERIMENTAL=1
export IMAGE=golang:1.23

# Scan for Go module vulnerabilities
trivy image --vuln-type os,library --ignore-unfixed -f json -o go-scan.json $IMAGE

# Apply patch-level Go module updates
copa patch \
    -i $IMAGE \
    -r go-scan.json \
    --pkg-types os,library \
    --library-patch-level patch
```

#### Go Limitations

##### Compiled Binary Limitations

**Critical Limitation**: Copa updates `go.mod` and `go.sum` files but **does not automatically rebuild compiled Go binaries**. This is the most important limitation to understand:

- **What Copa Does**: Updates `go.mod` and `go.sum` with fixed dependency versions
- **What Copa Doesn't Do**: Rebuild compiled binaries to include the fixed dependencies
- **Impact**: If your image contains a compiled Go binary, the binary will still contain vulnerable code even after Copa updates the module files

**Workflow for Compiled Binaries**:
1. Use Copa to update `go.mod` and `go.sum`
2. Extract the updated files from the patched image
3. Rebuild your Go application with the updated dependencies
4. Create a new image with the rebuilt binary

**Example**:
```bash
# Step 1: Patch the image (updates go.mod/go.sum only)
copa patch -i myapp:1.0 -r scan.json --pkg-types library -t myapp:1.0-patched

# Step 2: Extract updated module files
docker run --rm myapp:1.0-patched cat /app/go.mod > go.mod
docker run --rm myapp:1.0-patched cat /app/go.sum > go.sum

# Step 3: Rebuild your application
go build -o myapp ./cmd/myapp

# Step 4: Create new image with rebuilt binary
docker build -t myapp:1.0-fully-patched .
```

##### Go Module Detection

Copa searches for `go.mod` files in common Go project locations:
- `/app`
- `/go/src`
- `/usr/src/app`
- `/workspace`
- `/src`
- `/opt/app`

If your Go modules are in non-standard locations, Copa may not detect them automatically.

##### Dependency Resolution

Copa does not perform full dependency resolution for Go modules. It relies on `go get` and `go mod tidy` to handle dependency resolution, which may result in:

- Updated transitive dependencies beyond the explicitly patched modules
- Potential version conflicts if modules have strict version requirements
- Changes to `go.sum` that include dependencies not directly related to the vulnerability fixes

##### Go Version Compatibility

Copa does not check whether the updated Go modules are compatible with the Go version in the image. Module updates that require a newer Go version may fail to build or cause errors.

##### Replace Directives

Copa preserves existing `replace` directives in `go.mod` files during patching. However:

- New `replace` directives are not added automatically
- Conflicts between `replace` directives and vulnerability fixes are not automatically resolved
- Manual intervention may be required if a `replace` directive points to a vulnerable version

##### Tooling Container Strategy

When the Go toolchain is not present in the target image (e.g., distroless images):

- Copa uses a `golang:X.Y-alpine` tooling container to perform updates
- The Go version is detected from the image or defaults to Go 1.23
- Module files are copied to the tooling container, updated, and copied back
- This strategy only updates module files, not compiled binaries

##### Testing and Validation

Due to the limitations with compiled binaries and dependency resolution, it is **highly recommended** to:

1. Thoroughly test your application after applying updates
2. Verify that the updated modules are compatible with your Go version
3. Check that `go.sum` changes are expected and legitimate
4. Rebuild and test compiled binaries before deploying to production

Copa does not perform automated testing or validation of the patched application.
