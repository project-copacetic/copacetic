package provenance

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/moby/buildkit/client/llb"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
)

// normalizeVersion ensures a version string has the 'v' prefix required by Go modules.
func normalizeVersion(version string) string {
	if version == "" {
		return version
	}
	if strings.HasPrefix(version, "v") {
		return version
	}
	return "v" + version
}

// validateBinaryPath validates that a binary path is safe and absolute.
// It prevents path traversal attacks and ensures the path is suitable for use.
func validateBinaryPath(path string) error {
	if path == "" {
		return fmt.Errorf("binary path is empty")
	}

	// Must be absolute path
	if !filepath.IsAbs(path) {
		return fmt.Errorf("binary path must be absolute: %s", path)
	}

	// Check for path traversal attempts
	cleanPath := filepath.Clean(path)
	if cleanPath != path && !strings.HasPrefix(cleanPath, path) {
		// Allow minor normalization (trailing slashes, etc.)
		// but reject clear traversal patterns
		if strings.Contains(path, "..") {
			return fmt.Errorf("binary path contains traversal pattern: %s", path)
		}
	}

	// Reject paths that could escape expected locations
	if strings.Contains(path, "..") {
		return fmt.Errorf("binary path contains parent directory reference: %s", path)
	}

	// Reject paths with null bytes (injection attempt)
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("binary path contains null byte: %s", path)
	}

	// Reject paths with shell metacharacters
	if strings.ContainsAny(path, "|;&$`\\\"'<>(){}[]!#~") {
		return fmt.Errorf("binary path contains unsafe characters: %s", path)
	}

	return nil
}

// Rebuilder orchestrates the Go binary rebuild process using heuristic detection.
type Rebuilder struct{}

// NewRebuilder creates a new binary rebuilder.
func NewRebuilder() *Rebuilder {
	return &Rebuilder{}
}

// RebuildBinary rebuilds a Go binary with updated dependencies and merges it back into the target image.
func (r *Rebuilder) RebuildBinary(
	rebuildCtx *RebuildContext,
	updates map[string]string,
	platform *specs.Platform,
	targetState *llb.State,
	binaryPath string,
) (llb.State, *RebuildResult, error) {
	result := &RebuildResult{
		Strategy:        rebuildCtx.Strategy.String(),
		RebuiltBinaries: make(map[string]bool),
	}

	// Validate inputs with detailed error messages
	if rebuildCtx.Strategy == RebuildStrategyNone {
		result.Error = fmt.Errorf("no rebuild strategy available for binary %s", binaryPath)
		return llb.State{}, result, result.Error
	}

	buildInfo := rebuildCtx.BuildInfo
	if buildInfo == nil {
		result.Error = fmt.Errorf("no build information available for binary %s", binaryPath)
		return llb.State{}, result, result.Error
	}

	if targetState == nil {
		result.Error = fmt.Errorf("no target state provided for binary %s", binaryPath)
		return llb.State{}, result, result.Error
	}

	// Validate the binary path for security
	if err := validateBinaryPath(binaryPath); err != nil {
		result.Error = fmt.Errorf("invalid binary path: %w", err)
		return llb.State{}, result, result.Error
	}

	// Extract binary name from path (e.g., /coredns -> coredns)
	binaryName := filepath.Base(binaryPath)
	outputPath := "/output/" + binaryName

	log.Infof("Rebuilding Go binary %s using %s strategy", binaryPath, result.Strategy)
	log.Debugf("Binary details: module=%s, Go version=%s, %d dependencies",
		buildInfo.ModulePath, buildInfo.GoVersion, len(buildInfo.Dependencies))

	// Determine base image for build
	baseImage := r.determineBaseImage(buildInfo)
	if baseImage == "" {
		result.Error = fmt.Errorf("cannot determine base image for rebuild of %s: no Go version found (module: %s)",
			binaryPath, buildInfo.ModulePath)
		result.Warnings = append(result.Warnings, "No Go version found in binary info")
		return llb.State{}, result, result.Error
	}
	log.Infof("Using base image: %s", baseImage)

	// Build the new binary with updated dependencies (outputs to /output/<name>)
	buildState, err := r.buildBinaryWithUpdates(baseImage, buildInfo, updates, platform, outputPath)
	if err != nil {
		result.Error = fmt.Errorf("failed to rebuild binary %s (module: %s, Go: %s): %w",
			binaryPath, buildInfo.ModulePath, buildInfo.GoVersion, err)
		return llb.State{}, result, result.Error
	}

	// Copy the rebuilt binary from build container to target image
	// This is a pure LLB operation - works on distroless images (no shell needed)
	log.Infof("Copying rebuilt binary from %s to target at %s", outputPath, binaryPath)
	modifiedTarget := targetState.File(
		llb.Copy(buildState, outputPath, binaryPath, &llb.CopyInfo{
			CreateDestPath:      true,
			AllowWildcard:       false,
			AllowEmptyWildcard:  false,
			CopyDirContentsOnly: false,
		}),
	)

	// Capture only the diff (like dotnet patching)
	patchDiff := llb.Diff(*targetState, modifiedTarget)

	// Squash the diff into a single layer
	squashedPatch := llb.Scratch().File(
		llb.Copy(patchDiff, "/", "/", &llb.CopyInfo{
			CopyDirContentsOnly: true,
		}),
	)

	// Merge the patch back into the original image
	finalState := llb.Merge([]llb.State{*targetState, squashedPatch})

	result.Success = true
	result.BinariesRebuilt = 1
	result.RebuiltBinaries[binaryPath] = true

	log.Infof("Successfully merged rebuilt binary into target image")
	return finalState, result, nil
}

// rebuildToolingImage is the Go image used for rebuilding binaries with updated dependencies.
// We use the latest stable Go toolchain rather than matching the original binary's Go version
// because updated dependencies often require a newer Go version (e.g., golang.org/x/sys v0.38+
// requires Go 1.24). Go maintains strong backwards compatibility so using a newer toolchain
// to build an older codebase is safe.
const rebuildToolingImage = "golang:alpine"

// determineBaseImage selects the best base image for rebuilding.
func (r *Rebuilder) determineBaseImage(buildInfo *BuildInfo) string {
	if buildInfo.BaseImage != "" {
		return buildInfo.BaseImage
	}

	if buildInfo.GoVersion != "" {
		return rebuildToolingImage
	}

	return ""
}

// deriveRepoFromModulePath attempts to derive a Git repository URL from a Go module path.
func deriveRepoFromModulePath(modulePath string) (repoURL string, subpath string) {
	if modulePath == "" {
		return "", ""
	}

	// Handle github.com modules directly
	if strings.HasPrefix(modulePath, "github.com/") {
		parts := strings.Split(modulePath, "/")
		if len(parts) >= 3 {
			repoURL = fmt.Sprintf("https://github.com/%s/%s", parts[1], parts[2])
			if len(parts) > 3 {
				subpath = strings.Join(parts[3:], "/")
			}
			return repoURL, subpath
		}
	}

	// Handle k8s.io vanity imports -> github.com/kubernetes/*
	if strings.HasPrefix(modulePath, "k8s.io/") {
		parts := strings.SplitN(modulePath, "/", 3)
		if len(parts) >= 2 {
			repo := parts[1]
			repoURL = fmt.Sprintf("https://github.com/kubernetes/%s", repo)
			if len(parts) >= 3 {
				subpath = parts[2]
			}
			return repoURL, subpath
		}
	}

	// Handle golang.org/x/* -> github.com/golang/*
	if strings.HasPrefix(modulePath, "golang.org/x/") {
		parts := strings.SplitN(modulePath, "/", 4)
		if len(parts) >= 3 {
			repoURL = fmt.Sprintf("https://github.com/golang/%s", parts[2])
			if len(parts) >= 4 {
				subpath = parts[3]
			}
			return repoURL, subpath
		}
	}

	// Handle sigs.k8s.io/* -> github.com/kubernetes-sigs/*
	if strings.HasPrefix(modulePath, "sigs.k8s.io/") {
		parts := strings.SplitN(modulePath, "/", 3)
		if len(parts) >= 2 {
			repoURL = fmt.Sprintf("https://github.com/kubernetes-sigs/%s", parts[1])
			if len(parts) >= 3 {
				subpath = parts[2]
			}
			return repoURL, subpath
		}
	}

	return "", ""
}

// stripGoMajorVersionSuffix removes Go major version suffixes (v2, v3, etc.)
// from repository subpaths. In Go modules, paths like "github.com/foo/bar/v2"
// include /v2 to indicate major version 2, but the source code is typically at
// the repository root, not in a v2/ subdirectory.
func stripGoMajorVersionSuffix(subpath string) string {
	if subpath == "" {
		return ""
	}
	parts := strings.Split(subpath, "/")
	last := parts[len(parts)-1]
	if len(last) >= 2 && last[0] == 'v' {
		if n, err := strconv.Atoi(last[1:]); err == nil && n >= 2 {
			parts = parts[:len(parts)-1]
			return strings.Join(parts, "/")
		}
	}
	return subpath
}

// cloneSourceCode clones the source repository using BuildKit Git LLB.
func (r *Rebuilder) cloneSourceCode(buildInfo *BuildInfo) (llb.State, string, error) {
	repoURL := buildInfo.BuildArgs["_sourceRepo"]
	commit := buildInfo.BuildArgs["_sourceCommit"]
	subpath := ""

	// Without a specific commit/tag, don't attempt to clone
	if commit == "" {
		if repoURL != "" {
			log.Warnf("No commit/tag specified for %s - skipping clone", repoURL)
		}
		return llb.State{}, "", fmt.Errorf("no commit/tag specified for source clone")
	}

	// Always derive subpath from module path. For monorepo modules (e.g., k8s.io/autoscaler/cluster-autoscaler),
	// the module root lives in a subdirectory of the repository and we need subpath to set the correct workdir.
	if buildInfo.ModulePath != "" {
		derivedURL, derivedSubpath := deriveRepoFromModulePath(buildInfo.ModulePath)
		if repoURL == "" {
			repoURL = derivedURL
		}
		// Strip Go major version suffixes (v2, v3, ...) since these are module path
		// conventions, not actual subdirectories in most repositories.
		subpath = stripGoMajorVersionSuffix(derivedSubpath)
		if derivedURL != "" {
			log.Infof("Derived source repository from module path: %s (subpath: %q)", derivedURL, subpath)
		}
	}

	if repoURL == "" {
		return llb.State{}, "", fmt.Errorf("no source repository URL in build info")
	}

	log.Infof("Cloning source from %s @ %s", repoURL, commit)

	gitRef := repoURL
	if !strings.HasSuffix(gitRef, ".git") {
		gitRef += ".git"
	}
	if commit != "" {
		gitRef += "#" + commit
	}

	gitState := llb.Git(gitRef, commit, llb.KeepGitDir())
	log.Debugf("Created Git LLB state for %s", gitRef)
	return gitState, subpath, nil
}

// retryScript generates a shell script that retries a command with exponential backoff.
// It retries up to maxRetries times with delays of 1s, 2s, 4s, etc.
func retryScript(cmd string, maxRetries int) string {
	return fmt.Sprintf(`
retry=0
max_retry=%d
until %s; do
    retry=$((retry+1))
    if [ $retry -ge $max_retry ]; then
        echo "Command failed after $max_retry attempts: %s"
        exit 1
    fi
    delay=$((1 << (retry - 1)))
    echo "Attempt $retry failed, retrying in ${delay}s..."
    sleep $delay
done
`, maxRetries, cmd, strings.ReplaceAll(cmd, `"`, `\"`))
}

// buildBinaryWithUpdates creates a BuildKit LLB state that rebuilds the binary.
func (r *Rebuilder) buildBinaryWithUpdates(
	baseImage string,
	buildInfo *BuildInfo,
	updates map[string]string,
	platform *specs.Platform,
	outputPath string,
) (llb.State, error) {
	log.Debugf("Building binary with base image: %s, output path: %s", baseImage, outputPath)
	log.Debugf("Build info: module=%s, Go=%s, CGO=%v", buildInfo.ModulePath, buildInfo.GoVersion, buildInfo.CGOEnabled)

	var state llb.State
	if platform != nil {
		log.Debugf("Using platform: %s/%s", platform.OS, platform.Architecture)
		state = llb.Image(baseImage, llb.Platform(*platform))
	} else {
		state = llb.Image(baseImage)
	}

	workdir := "/build"
	if buildInfo.Workdir != "" {
		workdir = buildInfo.Workdir
	}

	// Try to clone source code from Git
	sourceCloned := false
	sourceState, subpath, err := r.cloneSourceCode(buildInfo)
	if err == nil {
		state = state.File(
			llb.Copy(sourceState, "/", workdir, &llb.CopyInfo{
				CreateDestPath: true,
			}),
		)
		sourceCloned = true
		if subpath != "" {
			workdir = filepath.Join(workdir, subpath)
			log.Infof("Cloned source code from Git repository, using subpath: %s", subpath)
		} else {
			log.Info("Cloned source code from Git repository")
		}
	} else {
		log.Debugf("Could not clone source (will generate go.mod): %v", err)
	}

	state = state.Dir(workdir)
	log.Debugf("Working directory: %s", workdir)

	// If we couldn't clone source, generate a minimal go.mod
	if !sourceCloned && buildInfo.ModulePath != "" {
		goMod := r.generateGoMod(buildInfo, updates)
		log.Debugf("Generated go.mod content:\n%s", goMod)
		state = state.File(llb.Mkdir(workdir, 0o755, llb.WithParents(true)))
		state = state.File(
			llb.Mkfile(filepath.Join(workdir, "go.mod"), 0o644, []byte(goMod)),
		)
		log.Info("Generated go.mod from dependency information")
	}

	goBin := "/usr/local/go/bin/go"

	// Install git (needed for go mod download)
	state = state.Run(
		llb.Shlex("apk add --no-cache git"),
	).Root()

	// Download dependencies with retry (network can be flaky)
	downloadCmd := fmt.Sprintf("%s mod download -x", goBin)
	downloadScript := retryScript(downloadCmd, 3)
	log.Debug("Running go mod download with retry...")
	state = state.Run(
		llb.Shlex(fmt.Sprintf("sh -c '%s'", strings.ReplaceAll(downloadScript, "'", "'\"'\"'"))),
		llb.WithProxy(llb.ProxyEnv{}),
	).Root()

	// Apply updates with retry for each module
	for module, version := range updates {
		normalizedVersion := normalizeVersion(version)
		log.Infof("Updating module %s: %s -> %s", module, buildInfo.Dependencies[module], normalizedVersion)

		getCmd := fmt.Sprintf("%s get %s@%s", goBin, module, normalizedVersion)
		getScript := retryScript(getCmd, 3)
		state = state.Run(
			llb.Shlex(fmt.Sprintf("sh -c '%s'", strings.ReplaceAll(getScript, "'", "'\"'\"'"))),
			llb.WithProxy(llb.ProxyEnv{}),
		).Root()
	}

	// Run mod tidy to sync go.sum after dependency updates.
	// This is needed both for generated go.mod and for cloned source where
	// go get may have added transitive dependencies not in the original go.sum.
	{
		log.Debug("Running go mod tidy...")
		state = state.Run(
			llb.Shlexf("%s mod tidy", goBin),
			llb.WithProxy(llb.ProxyEnv{}),
		).Root()
	}

	// Create output directory
	outputDir := filepath.Dir(outputPath)
	log.Debugf("Creating output directory: %s", outputDir)
	state = state.File(llb.Mkdir(outputDir, 0o755, llb.WithParents(true)))

	// Build the binary to the specified output path
	buildCmd := r.constructBuildCommand(buildInfo, goBin, outputPath)
	log.Infof("Build command: %s", buildCmd)
	state = state.Run(
		llb.Shlex(fmt.Sprintf("sh -c '%s'", strings.ReplaceAll(buildCmd, "'", "'\"'\"'"))),
		llb.WithProxy(llb.ProxyEnv{}),
	).Root()

	return state, nil
}

// generateGoMod generates a go.mod file from build information.
func (r *Rebuilder) generateGoMod(buildInfo *BuildInfo, updates map[string]string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("module %s\n\n", buildInfo.ModulePath))

	// Normalize Go version to major.minor format (strip patch version)
	// e.g., "1.20.4" -> "1.20"
	goVersion := buildInfo.GoVersion
	if parts := strings.Split(goVersion, "."); len(parts) >= 2 {
		goVersion = parts[0] + "." + parts[1]
	}
	sb.WriteString(fmt.Sprintf("go %s\n\n", goVersion))

	if len(buildInfo.Dependencies) > 0 || len(updates) > 0 {
		sb.WriteString("require (\n")

		for module, version := range buildInfo.Dependencies {
			if _, hasUpdate := updates[module]; hasUpdate {
				continue
			}
			if version == "v0.0.0" || version == "(devel)" {
				continue
			}
			sb.WriteString(fmt.Sprintf("\t%s %s\n", module, version))
		}

		for module, version := range updates {
			sb.WriteString(fmt.Sprintf("\t%s %s\n", module, normalizeVersion(version)))
		}

		sb.WriteString(")\n")
	}

	return sb.String()
}

// constructBuildCommand constructs a go build command from build info.
func (r *Rebuilder) constructBuildCommand(buildInfo *BuildInfo, goBin string, outputPath string) string {
	var parts []string

	if !buildInfo.CGOEnabled {
		parts = append(parts, "CGO_ENABLED=0")
	} else {
		parts = append(parts, "CGO_ENABLED=1")
	}

	if goos, ok := buildInfo.BuildArgs["GOOS"]; ok && goos != "" {
		parts = append(parts, fmt.Sprintf("GOOS=%s", goos))
	}
	if goarch, ok := buildInfo.BuildArgs["GOARCH"]; ok && goarch != "" {
		parts = append(parts, fmt.Sprintf("GOARCH=%s", goarch))
	}

	parts = append(parts, goBin, "build")

	// Add output path flag
	if outputPath != "" {
		parts = append(parts, "-o", outputPath)
	}

	parts = append(parts, buildInfo.BuildFlags...)

	mainPkg := buildInfo.MainPackage
	if mainPkg == "" {
		mainPkg = "."
	}
	parts = append(parts, mainPkg)

	return strings.Join(parts, " ")
}

// String returns string representation of RebuildStrategy.
func (s RebuildStrategy) String() string {
	switch s {
	case RebuildStrategyAuto:
		return "auto"
	case RebuildStrategyHeuristic:
		return "heuristic"
	case RebuildStrategyNone:
		return "none"
	default:
		return "unknown"
	}
}
