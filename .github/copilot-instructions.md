# Copacetic - Container Image Vulnerability Patching

## Project Overview
Copacetic (Copa) is a CLI tool that patches container image vulnerabilities using BuildKit. It applies OS package updates directly to container images without requiring full image rebuilds.

**Main command**: `copa patch -i IMAGE [-r REPORT] -t TAG`
**Module**: `github.com/project-copacetic/copacetic`

## Folder Structure
- `pkg/patch/`: CLI commands and core patching logic
- `pkg/buildkit/`: BuildKit integration and platform discovery
- `pkg/pkgmgr/`: Package manager adapters (dpkg, rpm, apk)
- `pkg/report/`: Vulnerability report parsing
- `pkg/types/`: Type definitions and configurations
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
- Write comprehensive tests for new functionality

## Key Architecture Concepts
- **Patching modes**: Targeted (with vulnerability reports) or comprehensive (all available updates)
- **Multi-platform support**: Handles amd64, arm64, and other architectures with QEMU emulation
- **Package managers**: Debian (apt/dpkg), RHEL (yum/rpm), Alpine (apk), Azure Linux (tdnf)
- **BuildKit integration**: Uses LLB operations for image building and manipulation

## Supported Operating Systems & Package Managers
- **Debian/Ubuntu**: Uses `dpkg` and `apt`
- **RHEL/CentOS/Rocky/Alma/Oracle/Amazon**: Uses `rpm` and `yum/dnf`
- **Alpine**: Uses `apk`
- **CBL-Mariner/Azure Linux**: Uses `rpm` and `tdnf`

## Key Functions
- `Patch()`: Main entry point for patching operations
- `patchSingleArchImage()` / `patchMultiPlatformImage()`: Core patching logic
- `DiscoverPlatformsFromReference()` / `DiscoverPlatformsFromReport()`: Platform discovery
- `InstallUpdates()`: Package manager interface for applying updates
