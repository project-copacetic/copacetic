# Copacetic - Container Image Vulnerability Patching

**ALWAYS reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.**

## Project Overview
Copacetic (Copa) is a CLI tool that patches container image vulnerabilities using BuildKit. It applies OS package updates directly to container images without requiring full image rebuilds.

**Main command**: `copa patch -i IMAGE [-r REPORT] -t TAG`
**Module**: `github.com/project-copacetic/copacetic`

## Working Effectively

### Bootstrap and Build
Run these commands in order to set up the development environment:

```bash
# Navigate to repository root
cd /home/runner/work/copacetic/copacetic

# Install development dependencies (golangci-lint, gofumpt)
make setup  # takes ~65 seconds, NEVER CANCEL, set timeout to 120+ seconds

# Build the copa binary  
make build  # takes ~57 seconds, NEVER CANCEL, set timeout to 120+ seconds

# Verify build works
./dist/linux_amd64/release/copa --version
./dist/linux_amd64/release/copa --help
```

### Configure Docker for Copa (REQUIRED)
Copa requires Docker with containerd image store enabled:

```bash
# Enable containerd snapshotter in Docker daemon
echo '{"features": { "containerd-snapshotter": true }}' | sudo tee /etc/docker/daemon.json
sudo systemctl restart docker

# Verify configuration
docker info | grep -i "driver-type.*containerd"
```

### Testing
```bash
# Run unit tests (takes ~36 seconds, some tests may fail without BuildKit setup)
make test  # NEVER CANCEL, set timeout to 120+ seconds

# Format code (takes ~0.05 seconds)
make format
```

### Linting (Known Issues)
```bash
# KNOWN ISSUE: golangci-lint version mismatch between config (v2) and binary (v1.64.8)
# Use formatting instead for code quality
make format

# If you need to run linter, temporarily rename config file:
mv .golangci.yml .golangci.yml.backup
export PATH="$(go env GOPATH)/bin:$PATH"
golangci-lint run -v ./...  # takes ~17 seconds with default config
mv .golangci.yml.backup .golangci.yml
```

## Validation

### Manual Testing Scenarios
ALWAYS manually validate copa functionality after making changes:

1. **Basic CLI Validation:**
   ```bash
   ./dist/linux_amd64/release/copa --version
   ./dist/linux_amd64/release/copa patch --help
   ```

2. **BuildKit Connection Test:**
   ```bash
   # Pull a small test image
   docker pull alpine:3.16
   
   # Test copa can connect to BuildKit (may fail on network, but should show BuildKit connection)
   ./dist/linux_amd64/release/copa patch -i alpine:3.16 --platform linux/amd64 --debug
   ```

3. **Expected Validation Output:**
   - `copa --version` should show version info
   - `copa patch --help` should show command help
   - Debug mode should show "Trying docker driver" and BuildKit connection attempts

### Always Run Before Committing
```bash
# ALWAYS run these before committing changes:
make format  # Format code with gofumpt
make build   # Ensure code builds successfully  
./dist/linux_amd64/release/copa --version  # Test basic functionality
```

## Repository Structure

### Key Directories
- `pkg/patch/` - CLI commands and core patching logic
- `pkg/buildkit/` - BuildKit integration and platform discovery  
- `pkg/pkgmgr/` - Package manager adapters (dpkg, rpm, apk)
- `pkg/report/` - Vulnerability report parsing and scanner plugin interface
- `pkg/imageloader/` - Container engine integration (Docker, Podman)
- `pkg/types/` - Type definitions and configurations
- `main.go` - Root CLI setup with Cobra framework
- `integration/` - Integration tests for multi-arch and single-arch scenarios
- `website/docs/` - Project documentation and user guides

### Key Files to Check After Changes
- Always check `main.go` after modifying CLI structure
- Always check `pkg/patch/` after modifying core functionality
- Always check `pkg/buildkit/` after modifying BuildKit integration

## Important Notes

### Timing Expectations
- **make build**: ~57 seconds - NEVER CANCEL, set timeout to 120+ seconds
- **make setup**: ~65 seconds - NEVER CANCEL, set timeout to 120+ seconds  
- **make test**: ~36 seconds - NEVER CANCEL, set timeout to 120+ seconds
- **make format**: ~0.05 seconds
- **golangci-lint**: ~17 seconds with default config

### Common Issues and Workarounds
1. **Linting fails**: Known golangci-lint version mismatch. Use `make format` instead.
2. **Tests fail with BuildKit errors**: Normal in sandboxed environments. Focus on build success and basic CLI validation.
3. **Network timeouts during copa patch**: Normal in restricted environments. Connection to BuildKit is the key validation point.

### Dependencies
- **Go 1.24+** (currently using go1.24.6)
- **Docker** with containerd image store enabled
- **BuildKit** (auto-detected from Docker daemon, buildx, or standalone)
- **golangci-lint and gofumpt** (installed via `make setup`)

### Architecture Support
Copa supports multiple platforms:
- **Debian/Ubuntu**: Uses `dpkg` and `apt`
- **RHEL/CentOS/Rocky/Alma/Oracle/Amazon**: Uses `rpm`, `yum`, and `dnf`  
- **Alpine**: Uses `apk`
- **CBL-Mariner/Azure Linux**: Uses `rpm` and `tdnf`

### Key Architecture Concepts
- **Patching modes**: Targeted (with vulnerability reports) or comprehensive (all available updates)
- **Multi-platform support**: Handles amd64, arm64, and other architectures with QEMU emulation
- **Package managers**: Debian (apt/dpkg), RHEL (yum/rpm), Alpine (apk), Azure Linux (tdnf)
- **BuildKit integration**: Uses LLB operations for image building and manipulation
- **Scanner plugins**: Supports custom vulnerability scanners via `customParseScanReport` interface

### Key Functions
- `Patch()`: Main entry point for patching operations
- `patchSingleArchImage()` / `patchMultiPlatformImage()`: Core patching logic
- `DiscoverPlatformsFromReference()` / `DiscoverPlatformsFromReport()`: Platform discovery
- `InstallUpdates()`: Package manager interface for applying updates
- `InitializeBuildkitConfig()`: Initializes BuildKit configuration for patching operations

### CI/CD Integration
The repository uses `.github/workflows/build.yml` for CI, which includes:
- Unit tests with 5-minute timeout
- Build verification with 5-minute timeout
- Integration tests with 30-minute timeout
- Multi-platform testing with emulation

Follow these patterns for reliable validation in your development workflow.

## Verified Commands Summary
All commands in these instructions have been validated in a fresh repository clone:

✅ **Build Process**: `make setup` + `make build` works reliably  
✅ **CLI Functionality**: `copa --version` and `copa --help` work correctly  
✅ **Code Formatting**: `make format` formats all Go files with gofumpt  
✅ **Docker Integration**: containerd image store configuration verified  
✅ **BuildKit Connection**: copa successfully connects to Docker's BuildKit backend  
✅ **Manual Validation**: All scenarios produce expected output  

These instructions are designed to help GitHub Copilot agents work effectively in the Copacetic codebase without encountering common setup pitfalls.
