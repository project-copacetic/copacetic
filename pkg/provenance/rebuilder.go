package provenance

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/moby/buildkit/client/llb"
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

// Rebuilder orchestrates the Go binary rebuild process using heuristic detection.
type Rebuilder struct{}

// NewRebuilder creates a new binary rebuilder.
func NewRebuilder() *Rebuilder {
	return &Rebuilder{}
}

// RebuildBinary rebuilds a Go binary with updated dependencies.
func (r *Rebuilder) RebuildBinary(
	rebuildCtx *RebuildContext,
	updates map[string]string,
) (llb.State, *RebuildResult, error) {
	result := &RebuildResult{
		Strategy: rebuildCtx.Strategy.String(),
	}

	if rebuildCtx.Strategy == RebuildStrategyNone {
		result.Error = fmt.Errorf("no rebuild strategy available")
		return llb.State{}, result, result.Error
	}

	buildInfo := rebuildCtx.BuildInfo
	if buildInfo == nil {
		result.Error = fmt.Errorf("no build information available")
		return llb.State{}, result, result.Error
	}

	log.Infof("Rebuilding Go binary using %s strategy", result.Strategy)

	// Determine base image for build
	baseImage := r.determineBaseImage(buildInfo)
	if baseImage == "" {
		result.Error = fmt.Errorf("cannot determine base image for rebuild")
		result.Warnings = append(result.Warnings, "No Go version found in binary info")
		return llb.State{}, result, result.Error
	}

	// Build the new binary with updated dependencies
	newState, err := r.buildBinaryWithUpdates(baseImage, buildInfo, updates)
	if err != nil {
		result.Error = fmt.Errorf("failed to rebuild binary: %w", err)
		return llb.State{}, result, result.Error
	}

	result.Success = true
	result.BinariesRebuilt = 1

	return newState, result, nil
}

// determineBaseImage selects the best base image for rebuilding.
func (r *Rebuilder) determineBaseImage(buildInfo *BuildInfo) string {
	if buildInfo.BaseImage != "" {
		return buildInfo.BaseImage
	}

	if buildInfo.GoVersion != "" {
		return fmt.Sprintf("golang:%s-alpine", buildInfo.GoVersion)
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

	// Try to derive from module path if no repo URL
	if repoURL == "" && buildInfo.ModulePath != "" {
		repoURL, subpath = deriveRepoFromModulePath(buildInfo.ModulePath)
		if repoURL != "" {
			log.Infof("Derived source repository from module path: %s (subpath: %s)", repoURL, subpath)
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

// buildBinaryWithUpdates creates a BuildKit LLB state that rebuilds the binary.
func (r *Rebuilder) buildBinaryWithUpdates(
	baseImage string,
	buildInfo *BuildInfo,
	updates map[string]string,
) (llb.State, error) {
	state := llb.Image(baseImage)

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

	// If we couldn't clone source, generate a minimal go.mod
	if !sourceCloned && buildInfo.ModulePath != "" {
		goMod := r.generateGoMod(buildInfo, updates)
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

	// Download dependencies
	state = state.Run(
		llb.Shlexf("%s mod download", goBin),
		llb.WithProxy(llb.ProxyEnv{}),
	).Root()

	// Apply updates
	for module, version := range updates {
		normalizedVersion := normalizeVersion(version)
		log.Infof("Updating %s to %s", module, normalizedVersion)
		state = state.Run(
			llb.Shlexf("%s get %s@%s", goBin, module, normalizedVersion),
			llb.WithProxy(llb.ProxyEnv{}),
		).Root()
	}

	// Only run mod tidy if we generated go.mod
	if !sourceCloned {
		state = state.Run(
			llb.Shlexf("%s mod tidy", goBin),
			llb.WithProxy(llb.ProxyEnv{}),
		).Root()
	}

	// Build the binary
	buildCmd := r.constructBuildCommand(buildInfo, goBin)
	log.Debugf("Build command: %s", buildCmd)
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
	sb.WriteString(fmt.Sprintf("go %s\n\n", buildInfo.GoVersion))

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
func (r *Rebuilder) constructBuildCommand(buildInfo *BuildInfo, goBin string) string {
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
