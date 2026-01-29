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

###### Node.js Testing and Validation

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

#### Experimental: Go Binary Rebuilding

:::warning Advanced Experimental Feature
Go binary rebuilding is an advanced experimental feature that requires additional flags beyond `COPA_EXPERIMENTAL=1`. This feature attempts to automatically rebuild Go binaries with updated dependencies using information from SLSA provenance and/or embedded build info.
:::

Copa has experimental support for automatically rebuilding Go binaries with patched dependencies. This feature addresses the main limitation of Go module patching by attempting to rebuild the actual binary, not just updating module files.

##### Enabling Binary Rebuild

```bash
export COPA_EXPERIMENTAL=1

# Patch Go binaries (binary rebuild happens automatically)
copa patch \
    -i $IMAGE \
    -r scan.json \
    --pkg-types library
```

##### How Binary Rebuilding Works

1. **SLSA Provenance Analysis**: Copa attempts to fetch SLSA provenance attestations from the container registry. If found, it extracts build information including Go version, build commands, and Dockerfile.

2. **GitHub Fallback**: If provenance doesn't contain the Dockerfile (common with `slsa-github-generator`), Copa fetches it from the source repository using the commit hash in provenance.

3. **Binary Detection**: If provenance is insufficient, Copa analyzes Go binaries in the image using `go version -m` to extract embedded build information.

4. **Source Cloning**: Copa clones the source repository at the provenance commit using BuildKit Git operations.

5. **Rebuild with Updates**: Copa rebuilds the binary with updated dependencies:
   - Applies `go get module@version` for each vulnerable dependency
   - Runs `go mod tidy` to clean up dependencies
   - Executes the original build command with detected flags

6. **Binary Replacement**: The rebuilt binary is copied back to its original location in the image.

##### Binary Rebuild Requirements

For binary rebuilding to work, the image should have one or more of:

- **SLSA Provenance**: Built with `slsa-github-generator` or BuildKit with `--provenance=max`
- **Embedded Build Info**: Go binaries built with `-buildinfo` (default since Go 1.18)
- **Public Source Repository**: Source code accessible on GitHub at the provenance commit

##### Supported SLSA Provenance Versions

- SLSA v0.2 (common from slsa-github-generator)
- SLSA v1.0 (newer provenance format)

##### Binary Rebuild Limitations

1. **Private Repositories**: Currently only public GitHub repositories are supported for source cloning and Dockerfile fetching.

2. **Complex Builds**: Multi-stage Dockerfiles, custom build scripts, and CGO-dependent builds may not rebuild correctly.

3. **Non-Go Tools**: The binary rebuild process requires standard Go toolchain. Builds using custom compilers or tools may fail.

4. **Build Reproducibility**: Rebuilt binaries may differ from originals due to timestamps, Go version differences, or non-deterministic build steps.

##### Example with Binary Rebuild

```bash
export COPA_EXPERIMENTAL=1

# Image built with slsa-github-generator provenance
export IMAGE=ghcr.io/fluxcd/source-controller:v1.2.0

# Scan for vulnerabilities
trivy image --vuln-type library --ignore-unfixed -f json -o scan.json $IMAGE

# Patch with binary rebuilding
copa patch \
    -i $IMAGE \
    -r scan.json \
    --pkg-types library \
    -t patched

# Verify the patched binary
trivy image patched --vuln-type library
```

##### Rebuild Strategy

Copa requires SLSA provenance for binary rebuilding:

1. **Provenance Strategy**: Uses SLSA provenance with GitHub-enriched Dockerfile (requires `--provenance=max`)
2. **go.mod Only**: Falls back to updating module files only if provenance is not available

The strategy used is logged during patching:

```text
INFO Using rebuild strategy: provenance
INFO Binary rebuild successful: 1 binaries rebuilt
```

Or when provenance is not available:

```text
INFO No rebuild strategy available (SLSA provenance required), will only update go.mod/go.sum
```

> **Note**: Binary rebuild requires images built with SLSA provenance (`docker buildx build --provenance=max`). Images without provenance will only have their go.mod/go.sum files updated.

### .NET

Copa supports patching .NET applications by replacing vulnerable DLLs in-place. This approach works for both SDK-based images and runtime-only images using the same flags as noted above.

#### How .NET Patching Works

##### Application Discovery

Copa automatically locates your application by searching for `*.deps.json` files across the entire filesystem, excluding system paths that contain SDK tooling and cached packages:

```
find / -name "*.deps.json" | grep -v "^/usr/share/" | grep -v "^/usr/local/share/" | grep -v "^/root/.nuget" | grep -v "^/tmp/"
```

This approach:
- Works for any deployment location (including custom `-o` output paths)
- Automatically handles images where apps are deployed to `/app`, `/home`, `/opt`, or any other directory
- Excludes SDK tools, NuGet cache, and temporary files from discovery

##### Patching Process

1. **Discovery**: Searches filesystem for `*.deps.json`, extracts framework version (e.g., `8.0.11`)
2. **SDK Container**: Creates temporary SDK container with matching framework version, with a default of `8.0` (e.g., `mcr.microsoft.com/dotnet/sdk:8.0.11`)
3. **Build Fixed Packages**: Creates temp project with `PackageReference` entries for fixed versions, runs `dotnet publish` to download and compile
4. **DLL Replacement**: Copies patched DLLs to app directory, only replacing files that already exist (won't add new DLLs)
5. **Metadata Update**: Uses `jq` to merge package entries from the generated `deps.json` into the original, preserving correct `sha512`, `hashPath`, `assemblyVersion`, and `fileVersion` metadata
6. **Layer Optimization**: Diffs from original image to capture only actual changes, then squashes into a single patch layer

##### Why DLL Replacement Works

NuGet packages contain pre-compiled IL bytecode (not native code). The .NET runtime JIT-compiles at load time, so DLLs can be swapped without recompilation.

##### deps.json Metadata

The `deps.json` file contains critical metadata for each package:
- **sha512**: Hash of the package for integrity verification
- **hashPath**: Path to the `.nupkg.sha512` file
- **assemblyVersion**: CLR assembly version
- **fileVersion**: File version for native image binding

Copa generates correct metadata by using `dotnet publish` in an SDK container and extracting the package entries with `jq`.

#### Important Considerations

**Patch Level**: Many .NET security fixes involve major version changes (e.g., `12.0.1 → 13.0.1`). Use `--library-patch-level major` to allow these updates.

**Validation**: Copa verifies that patched DLLs are successfully copied to the app directory. The updated `deps.json` is verified to contain the new package versions. However, runtime compatibility is not tested.

**Multi-Application Containers**: Only the first discovered application is patched. Split multi-app containers for proper patching.

**Non-Vulnerable Packages**: Packages that are not in the vulnerability report remain unchanged. Only vulnerable packages are updated.

**Ignore Errors**: Use `--ignore-errors` to continue patching even if some packages fail. This is useful when:
- Some packages have dependency conflicts
- A package version is unavailable on NuGet
- You want to patch as many vulnerabilities as possible

:::danger DLL Replacement Bypasses Compilation
API incompatibilities won't surface until runtime. Always test in staging before production.
:::

#### .NET Limitations

##### Microsoft.Build.* Packages

Copa automatically filters out `Microsoft.Build.*` packages from patching. These are SDK/build-time dependencies that:
- Are not part of the runtime application
- Often have version constraints incompatible with patching
- Don't represent actual security vulnerabilities in the deployed application

##### Dependency Resolution

Copa does not perform full dependency resolution. It applies updates based on scanner results. If updating a package causes dependency conflicts, you may need to:
- Use `--ignore-errors` to continue patching other packages
- Manually resolve version conflicts in your `.csproj` file
