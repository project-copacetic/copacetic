package provenance

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/moby/buildkit/client/llb"
	log "github.com/sirupsen/logrus"
)

// Rebuilder orchestrates the binary rebuild process using SLSA provenance.
type Rebuilder struct {
	fetcher *Fetcher
	parser  *Parser
}

// NewRebuilder creates a new binary rebuilder.
func NewRebuilder() *Rebuilder {
	return &Rebuilder{
		fetcher: NewFetcher(),
		parser:  NewParser(),
	}
}

// AnalyzeImage analyzes an image to determine the best rebuild strategy.
func (r *Rebuilder) AnalyzeImage(ctx context.Context, imageRef string, imageRoot string) (*RebuildContext, error) {
	log.Infof("Analyzing image for Go binary rebuild: %s", imageRef)

	rebuildCtx := &RebuildContext{
		Strategy: RebuildStrategyNone,
	}

	// Step 1: Try to fetch SLSA provenance
	attestation, err := r.fetcher.FetchAttestation(ctx, imageRef)
	if err != nil {
		log.Debugf("No SLSA provenance available: %v", err)
	} else {
		rebuildCtx.Provenance = attestation

		// Parse build info from provenance
		buildInfo, err := r.parser.ParseBuildInfo(attestation)
		if err != nil {
			log.Warnf("Failed to parse provenance build info: %v", err)
		} else {
			rebuildCtx.BuildInfo = buildInfo
			rebuildCtx.Completeness = r.parser.AssessCompleteness(buildInfo)

			// Step 1.5: If provenance is incomplete, try GitHub fallback
			if !rebuildCtx.Completeness.CanRebuild || rebuildCtx.BuildInfo.Dockerfile == "" {
				log.Info("Provenance incomplete, attempting GitHub fallback...")
				r.enrichFromGitHub(ctx, rebuildCtx)
				rebuildCtx.Completeness = r.parser.AssessCompleteness(buildInfo)
			}

			if rebuildCtx.Completeness.CanRebuild {
				rebuildCtx.Strategy = RebuildStrategyProvenance
				log.Info("SLSA provenance (possibly enriched from GitHub) is complete enough for rebuild")
				return rebuildCtx, nil
			}

			log.Infof("SLSA provenance incomplete (missing: %v), binary rebuild not possible",
				rebuildCtx.Completeness.MissingInfo)
		}
	}

	// Note: Heuristic binary detection has been removed for v1.
	// Only SLSA provenance-based rebuild is supported.
	// See: https://github.com/project-copacetic/copacetic/pull/1388

	log.Info("No rebuild strategy available (SLSA provenance required), will only update go.mod/go.sum")
	return rebuildCtx, nil
}

// enrichFromGitHub enriches the rebuild context with information from GitHub.
// This is called when provenance lacks Dockerfile or other critical build information.
func (r *Rebuilder) enrichFromGitHub(ctx context.Context, rebuildCtx *RebuildContext) {
	if rebuildCtx.Provenance == nil {
		return
	}

	// Extract source repo from provenance
	repoURL, commit, err := r.parser.ExtractSourceRepo(rebuildCtx.Provenance)
	if err != nil {
		log.Debugf("Could not extract source repo from provenance: %v", err)
		return
	}

	if repoURL == "" || commit == "" {
		log.Debug("No source repo or commit found in provenance")
		return
	}

	log.Infof("Found source repository in provenance: %s @ %s", repoURL, commit)

	// Initialize buildInfo if nil
	if rebuildCtx.BuildInfo == nil {
		rebuildCtx.BuildInfo = &BuildInfo{
			BuildArgs: make(map[string]string),
		}
	}

	// Enrich from GitHub
	if err := r.fetcher.EnrichBuildInfoFromGitHub(ctx, rebuildCtx.BuildInfo, repoURL, commit); err != nil {
		log.Warnf("Failed to enrich build info from GitHub: %v", err)
	}
}


// RebuildBinary rebuilds a Go binary with updated dependencies.
func (r *Rebuilder) RebuildBinary(
	ctx context.Context,
	rebuildCtx *RebuildContext,
	baseState *llb.State,
	updates map[string]string, // module -> new version
) (*llb.State, *RebuildResult, error) {
	result := &RebuildResult{
		Strategy: rebuildCtx.Strategy.String(),
	}

	if rebuildCtx.Strategy == RebuildStrategyNone {
		result.Error = fmt.Errorf("no rebuild strategy available")
		return baseState, result, result.Error
	}

	buildInfo := rebuildCtx.BuildInfo
	if buildInfo == nil {
		result.Error = fmt.Errorf("no build information available")
		return baseState, result, result.Error
	}

	log.Infof("Rebuilding Go binary using %s strategy", result.Strategy)

	// Determine base image for build
	baseImage := r.determineBaseImage(buildInfo)
	if baseImage == "" {
		result.Error = fmt.Errorf("cannot determine base image for rebuild")
		result.Warnings = append(result.Warnings, "No base image found in provenance or binary info")
		return baseState, result, result.Error
	}

	// Build the new binary with updated dependencies
	newState, err := r.buildBinaryWithUpdates(baseImage, buildInfo, updates)
	if err != nil {
		result.Error = fmt.Errorf("failed to rebuild binary: %w", err)
		return baseState, result, result.Error
	}

	result.Success = true
	result.BinaryPatched = true
	result.BinariesRebuilt = 1

	return &newState, result, nil
}

// determineBaseImage selects the best base image for rebuilding.
func (r *Rebuilder) determineBaseImage(buildInfo *BuildInfo) string {
	// Prefer explicit base image from provenance
	if buildInfo.BaseImage != "" {
		return buildInfo.BaseImage
	}

	// Fall back to constructing from Go version
	if buildInfo.GoVersion != "" {
		// Use alpine for smaller images
		return fmt.Sprintf("golang:%s-alpine", buildInfo.GoVersion)
	}

	return ""
}

// cloneSourceCode clones the source repository using BuildKit Git LLB.
// Returns an LLB state with the source code at /src.
func (r *Rebuilder) cloneSourceCode(buildInfo *BuildInfo) (llb.State, error) {
	// Extract source repo URL and commit from build info
	repoURL := buildInfo.BuildArgs["_sourceRepo"]
	commit := buildInfo.BuildArgs["_sourceCommit"]

	if repoURL == "" {
		return llb.State{}, fmt.Errorf("no source repository URL in build info")
	}

	log.Infof("Cloning source from %s @ %s", repoURL, commit)

	// Use BuildKit Git LLB to clone the repository
	// Format: https://github.com/owner/repo.git#commit
	gitRef := repoURL
	if !strings.HasSuffix(gitRef, ".git") {
		gitRef += ".git"
	}
	if commit != "" {
		gitRef += "#" + commit
	}

	// Clone the repository
	gitState := llb.Git(gitRef, commit, llb.KeepGitDir())

	log.Debugf("Created Git LLB state for %s", gitRef)
	return gitState, nil
}

// buildBinaryWithUpdates creates a BuildKit LLB state that rebuilds the binary.
func (r *Rebuilder) buildBinaryWithUpdates(
	baseImage string,
	buildInfo *BuildInfo,
	updates map[string]string,
) (llb.State, error) {
	// Start from Go build image
	state := llb.Image(baseImage)

	// Determine workdir - use module path structure if available
	workdir := "/build"
	if buildInfo.Workdir != "" {
		workdir = buildInfo.Workdir
	}

	// Try to clone source code from Git
	sourceCloned := false
	sourceState, err := r.cloneSourceCode(buildInfo)
	if err == nil {
		// Copy source code to build container
		state = state.File(
			llb.Copy(sourceState, "/", workdir, &llb.CopyInfo{
				CreateDestPath: true,
			}),
		)
		sourceCloned = true
		log.Info("Cloned source code from Git repository")
	} else {
		log.Debugf("Could not clone source (will generate go.mod): %v", err)
	}

	state = state.Dir(workdir)

	// If we couldn't clone source, generate a minimal go.mod
	if !sourceCloned && buildInfo.ModulePath != "" {
		goMod := r.generateGoMod(buildInfo, updates)
		state = state.File(
			llb.Mkfile(filepath.Join(workdir, "go.mod"), 0o644, []byte(goMod)),
		)
		log.Info("Generated go.mod from dependency information")
	}

	// Download dependencies
	state = state.Run(
		llb.Shlex("go mod download"),
		llb.WithProxy(llb.ProxyEnv{}),
	).Root()

	// Apply updates to dependencies
	for module, version := range updates {
		log.Infof("Updating %s to %s", module, version)
		state = state.Run(
			llb.Shlexf("go get %s@%s", module, version),
			llb.WithProxy(llb.ProxyEnv{}),
		).Root()
	}

	// Tidy dependencies
	state = state.Run(
		llb.Shlex("go mod tidy"),
		llb.WithProxy(llb.ProxyEnv{}),
	).Root()

	// Build the binary
	buildCmd := r.constructBuildCommand(buildInfo)
	log.Debugf("Build command: %s", buildCmd)
	state = state.Run(
		llb.Shlex(buildCmd),
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

		// Add existing dependencies
		for module, version := range buildInfo.Dependencies {
			// Skip if we have an update for this module
			if _, hasUpdate := updates[module]; hasUpdate {
				continue
			}
			sb.WriteString(fmt.Sprintf("\t%s %s\n", module, version))
		}

		// Add updated dependencies
		for module, version := range updates {
			sb.WriteString(fmt.Sprintf("\t%s %s\n", module, version))
		}

		sb.WriteString(")\n")
	}

	return sb.String()
}

// constructBuildCommand constructs a go build command from build info.
func (r *Rebuilder) constructBuildCommand(buildInfo *BuildInfo) string {
	var parts []string

	// Start with CGO setting
	if !buildInfo.CGOEnabled {
		parts = append(parts, "CGO_ENABLED=0")
	} else {
		parts = append(parts, "CGO_ENABLED=1")
	}

	// Add GOOS/GOARCH if specified
	if goos, ok := buildInfo.BuildArgs["GOOS"]; ok && goos != "" {
		parts = append(parts, fmt.Sprintf("GOOS=%s", goos))
	}
	if goarch, ok := buildInfo.BuildArgs["GOARCH"]; ok && goarch != "" {
		parts = append(parts, fmt.Sprintf("GOARCH=%s", goarch))
	}

	// Build command
	parts = append(parts, "go", "build")

	// Add build flags
	parts = append(parts, buildInfo.BuildFlags...)

	// Add main package or default to current directory
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
	case RebuildStrategyProvenance:
		return "provenance"
	case RebuildStrategyNone:
		return "none"
	default:
		return "unknown"
	}
}

// RebuildError represents an error during the rebuild process with detailed context.
type RebuildError struct {
	Phase       string // Phase where error occurred (analysis, clone, build, copy)
	Message     string
	Underlying  error
	Recoverable bool // Whether fallback to go.mod update is possible
	Suggestions []string
}

func (e *RebuildError) Error() string {
	if e.Underlying != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Phase, e.Message, e.Underlying)
	}
	return fmt.Sprintf("[%s] %s", e.Phase, e.Message)
}

func (e *RebuildError) Unwrap() error {
	return e.Underlying
}

// newRebuildError creates a new rebuild error with context.
func newRebuildError(phase, message string, underlying error, recoverable bool, suggestions ...string) *RebuildError {
	return &RebuildError{
		Phase:       phase,
		Message:     message,
		Underlying:  underlying,
		Recoverable: recoverable,
		Suggestions: suggestions,
	}
}

// RebuildWithFallback attempts to rebuild using SLSA provenance.
// Note: Heuristic binary detection has been removed for v1 - only SLSA provenance is supported.
func (r *Rebuilder) RebuildWithFallback(
	ctx context.Context,
	rebuildCtx *RebuildContext,
	baseState *llb.State,
	updates map[string]string,
) (*llb.State, *RebuildResult, error) {
	result := &RebuildResult{
		Strategy: rebuildCtx.Strategy.String(),
	}

	// Only provenance-based rebuild is supported
	if rebuildCtx.Strategy == RebuildStrategyProvenance && rebuildCtx.BuildInfo != nil {
		log.Info("Attempting provenance-based rebuild...")

		newState, rebuildResult, err := r.RebuildBinary(ctx, rebuildCtx, baseState, updates)
		if err == nil && rebuildResult.Success {
			return newState, rebuildResult, nil
		}

		result.Warnings = append(result.Warnings, fmt.Sprintf("Provenance rebuild failed: %v", err))
		log.Warnf("Provenance-based rebuild failed: %v", err)

		result.Success = false
		result.Error = newRebuildError(
			"rebuild",
			"provenance-based rebuild failed",
			err,
			true, // Recoverable - can fall back to go.mod update
			"Ensure the image has SLSA provenance with BuildKit metadata (provenance=max)",
			"Check that provenance includes Dockerfile and build commands",
		)
		return baseState, result, result.Error
	}

	// No valid strategy available
	result.Success = false
	result.Error = newRebuildError(
		"rebuild",
		"no rebuild strategy available (SLSA provenance required)",
		nil,
		true, // Recoverable - can fall back to go.mod update
		"Binary rebuild requires SLSA provenance with BuildKit metadata",
		"Build images with: docker buildx build --provenance=max",
		"Or use slsa-github-generator for GitHub Actions builds",
	)

	return baseState, result, result.Error
}

// DiagnoseRebuildIssue analyzes why rebuild might not be possible and provides suggestions.
func (r *Rebuilder) DiagnoseRebuildIssue(rebuildCtx *RebuildContext) []string {
	var issues []string

	if rebuildCtx == nil {
		issues = append(issues, "No rebuild context available")
		return issues
	}

	// Check provenance
	if rebuildCtx.Provenance == nil {
		issues = append(issues, "No SLSA provenance found for image. Try using images built with slsa-github-generator or BuildKit provenance=max")
	} else if rebuildCtx.Completeness != nil && len(rebuildCtx.Completeness.MissingInfo) > 0 {
		issues = append(issues, fmt.Sprintf("Provenance missing: %v", rebuildCtx.Completeness.MissingInfo))
	}

	// Check build info
	if rebuildCtx.BuildInfo == nil {
		issues = append(issues, "No build information extracted from provenance")
	} else {
		if rebuildCtx.BuildInfo.GoVersion == "" {
			issues = append(issues, "Go version not detected - cannot determine build toolchain")
		}
		if rebuildCtx.BuildInfo.ModulePath == "" {
			issues = append(issues, "Module path not detected - cannot set up Go module")
		}
		if rebuildCtx.BuildInfo.Dockerfile == "" {
			issues = append(issues, "Dockerfile not in provenance - consider using BuildKit with provenance=max")
		}
	}

	if len(issues) == 0 {
		issues = append(issues, "Build information appears complete - rebuild should be possible")
	}

	return issues
}

// FormatRebuildSummary creates a human-readable summary of the rebuild attempt.
func (r *Rebuilder) FormatRebuildSummary(rebuildCtx *RebuildContext, result *RebuildResult) string {
	var sb strings.Builder

	sb.WriteString("\n=== Go Binary Rebuild Summary ===\n\n")

	// Strategy used
	sb.WriteString(fmt.Sprintf("Strategy: %s\n", result.Strategy))
	sb.WriteString(fmt.Sprintf("Success: %v\n", result.Success))

	// Build info if available
	if rebuildCtx != nil && rebuildCtx.BuildInfo != nil {
		sb.WriteString("\nBuild Information:\n")
		sb.WriteString(fmt.Sprintf("  Go Version: %s\n", rebuildCtx.BuildInfo.GoVersion))
		sb.WriteString(fmt.Sprintf("  Module: %s\n", rebuildCtx.BuildInfo.ModulePath))
		sb.WriteString(fmt.Sprintf("  CGO Enabled: %v\n", rebuildCtx.BuildInfo.CGOEnabled))
		if rebuildCtx.BuildInfo.Dockerfile != "" {
			sb.WriteString("  Dockerfile: Available\n")
		} else {
			sb.WriteString("  Dockerfile: Not available\n")
		}
	}

	// Results
	if result.Success {
		sb.WriteString(fmt.Sprintf("\nBinaries Rebuilt: %d\n", result.BinariesRebuilt))
	} else if result.Error != nil {
		sb.WriteString(fmt.Sprintf("\nError: %v\n", result.Error))
	}

	// Warnings
	if len(result.Warnings) > 0 {
		sb.WriteString("\nWarnings:\n")
		for _, w := range result.Warnings {
			sb.WriteString(fmt.Sprintf("  - %s\n", w))
		}
	}

	// Suggestions for failure
	if !result.Success && rebuildCtx != nil {
		issues := r.DiagnoseRebuildIssue(rebuildCtx)
		if len(issues) > 0 {
			sb.WriteString("\nSuggestions:\n")
			for _, issue := range issues {
				sb.WriteString(fmt.Sprintf("  - %s\n", issue))
			}
		}
	}

	return sb.String()
}
