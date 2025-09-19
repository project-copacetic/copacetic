# Copacetic - Container Image Vulnerability Patching

## Project Overview
Copacetic (Copa) is a CLI tool that patches container image vulnerabilities using BuildKit. It applies OS package updates directly to container images without requiring full image rebuilds.

**Main command**: `copa patch -i IMAGE [-r REPORT] -t TAG`
**Module**: `github.com/project-copacetic/copacetic`

## Folder Structure
- `pkg/patch/`: CLI commands and core patching logic
- `pkg/buildkit/`: BuildKit integration and platform discovery
- `pkg/pkgmgr/`: OS package manager adapters (dpkg, rpm, apk)
- `pkg/langmgr/`: Language (application/library) package managers (e.g. Python/pip)
- `pkg/report/`: Vulnerability report parsing and scanner plugin interface
- `pkg/imageloader/`: Container engine integration (Docker, Podman)
- `pkg/types/`: Type definitions and configurations
- `website/docs/`: Project documentation and user guides
- `integration/`: Integration tests for multi-arch and single-arch scenarios (OS + language flows)
- `main.go`: Root CLI setup with Cobra framework

## Libraries and Frameworks
- BuildKit for container image manipulation
- Cobra for CLI framework
- Trivy as default vulnerability scanner
- Logrus for structured logging
- Go Container Registry libraries for image operations

## Coding Standards
- Follow Go best practices and `golangci-lint` rules
- Use structured logging with `logrus`
- Implement proper error wrapping with `fmt.Errorf`
- Write comprehensive tests for new functionality:
  - Unit tests for individual functions and components
  - Integration tests for end-to-end patching scenarios
- Add relevant documentation for new functionality in `website/docs/`

## Key Architecture Concepts
- **Patching modes**: Targeted (with vulnerability reports) or comprehensive (all available updates)
- **Multi-platform support**: Handles amd64, arm64, and other architectures with QEMU emulation
- **OS package managers**: Debian (apt/dpkg), RHEL family (yum/rpm/dnf/microdnf/tdnf), Alpine (apk), Azure Linux / CBL-Mariner (tdnf)
- **Language (application/library) patching**: Experimental support for upgrading vulnerable application dependencies (currently Python via pip) with semantic version / patch-level controls.
- **BuildKit integration**: Uses LLB operations for image building and manipulation
- **Scanner plugins**: Supports custom vulnerability scanners via `customParseScanReport` interface
- **Selective package types**: User can choose to patch only OS, only library, or both via `--pkg-types`.

## Supported Targets
### Operating Systems (OS package layer)
- **Debian/Ubuntu**: `dpkg` + `apt`
- **RHEL/CentOS/Rocky/Alma/Oracle/Amazon**: `rpm`, `yum`, `dnf`, `microdnf`, `tdnf` (as available)
- **Alpine**: `apk`
- **CBL-Mariner/Azure Linux**: `rpm` + `tdnf`

### Language / Application Dependencies (Experimental)
- **Python**: pip-based site-packages upgrades with version validation and patch-level selection.
  - Controlled via `--pkg-types library` (or `os,library`) and `--library-patch-level`.
  - Patch levels: `patch` (default), `minor`, `major`; influences chosen fixed version when multiple are available.
  - Special per-package overrides supported (see `getSpecialPackagePatchLevels()` inside Python manager for curated exceptions).

## Key Functions

### CLI / Orchestration
- `Patch()`: Main entry point for patching operations
- `patchSingleArchImage()` / `patchMultiPlatformImage()`: Core patching logic
- `DiscoverPlatformsFromReference()` / `DiscoverPlatformsFromReport()`: Platform discovery
- `InitializeBuildkitConfig()`: Initializes BuildKit configuration for patching operations

### OS Package Layer
- `pkgmgr.GetPackageManager()` and concrete managers' `InstallUpdates()` methods
- `GetUniqueLatestUpdates()` (OS) for deduplicating + selecting latest OS package versions

### Language / Library Layer
- `langmgr.GetLanguageManagers()` returns appropriate language managers based on manifest content
- `pythonManager.InstallUpdates()` coordinates: selecting versions, performing pip upgrades, validating results
- `langmgr.GetUniqueLatestUpdates()` (libraries) similar to OS but tolerant of empty sets & patch-level filtering
- `FindOptimalFixedVersionWithPatchLevel()` (Trivy parsing path) chooses best fixed version under patch-level constraint

### Report Parsing & Filtering
- `report.TryParseScanReport()` / Trivy parser: builds unified UpdateManifest (OS + Lang)
- Filtering by `--pkg-types` occurs early and again before build execution for safety.

### Validation & VEX
- `vex.TryOutputVexDocument()` generates optional VEX documents (only if report + updates applied)

## Language Patching
Language/library patching is gated behind `COPA_EXPERIMENTAL=1`.

- `--pkg-types`: comma list of `os`, `library` (default `os`). Determines which sections of the UpdateManifest are acted upon.
- `--library-patch-level`: one of `patch|minor|major` (default `patch`). Sets semantic version boundary for chosen upgrade version.
- Behavior when report only has library vulns:
  - If `--pkg-types` includes `library`, proceed (even if no OS updates). Empty OS set no longer triggers an error.
  - If `--pkg-types os` only, library updates are ignored (manifest language section cleared early).

## Library Patching Flow (Python)
1. Trivy report parsed -> vulnerable Python packages aggregated with all candidate fixed versions.
2. Patch level rule applied to select optimal fixed version per package (with per-package override map for exceptions).
3. Upgrade executed in ephemeral tooling container (derives base Python image tag when possible; fallback tag `3-slim`).
4. Post-upgrade validation via `pip freeze` subset matching: ensures requested versions actually installed.
5. Failed installs or mismatches collected; errors either propagate or are logged based on `--ignore-errors`.
6. Validated updates merged into final manifest fed to VEX generation.
