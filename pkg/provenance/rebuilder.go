package provenance

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/moby/buildkit/client/llb"
	log "github.com/sirupsen/logrus"
)

// Rebuilder orchestrates the binary rebuild process using provenance and/or binary detection.
type Rebuilder struct {
	fetcher  *Fetcher
	parser   *Parser
	detector *Detector
}

// NewRebuilder creates a new binary rebuilder.
func NewRebuilder() *Rebuilder {
	return &Rebuilder{
		fetcher:  NewFetcher(),
		parser:   NewParser(),
		detector: NewDetector(),
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

			if rebuildCtx.Completeness.CanRebuild {
				rebuildCtx.Strategy = RebuildStrategyProvenance
				log.Info("SLSA provenance is complete enough for rebuild")
				return rebuildCtx, nil
			}

			log.Infof("SLSA provenance incomplete (missing: %v), will try binary detection",
				rebuildCtx.Completeness.MissingInfo)
		}
	}

	// Step 2: Try binary detection as fallback
	if imageRoot != "" {
		binaryInfos, err := r.detectBinariesInImage(imageRoot)
		if err != nil {
			log.Warnf("Binary detection failed: %v", err)
		} else if len(binaryInfos) > 0 {
			rebuildCtx.BinaryInfo = binaryInfos
			rebuildCtx.Strategy = RebuildStrategyHeuristic

			// If we have both provenance and binary info, merge them
			if rebuildCtx.BuildInfo != nil {
				r.mergeBuildInfo(rebuildCtx)
			} else {
				// Convert binary info to build info
				rebuildCtx.BuildInfo = r.detector.ConvertBinaryInfoToBuildInfo(binaryInfos[0])
			}

			// Re-assess completeness with merged info
			rebuildCtx.Completeness = r.parser.AssessCompleteness(rebuildCtx.BuildInfo)

			log.Infof("Binary detection found %d Go binaries", len(binaryInfos))
			return rebuildCtx, nil
		}
	}

	log.Info("No rebuild strategy available, will only update go.mod/go.sum")
	return rebuildCtx, nil
}

// detectBinariesInImage finds and analyzes Go binaries in an extracted image.
func (r *Rebuilder) detectBinariesInImage(imageRoot string) ([]*BinaryInfo, error) {
	// Find potential binaries
	candidates, err := r.detector.FindBinariesInImage(imageRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to find binaries: %w", err)
	}

	// Filter to only Go binaries and detect their info
	var binaryInfos []*BinaryInfo

	for _, candidate := range candidates {
		if !r.detector.IsGoBinary(candidate) {
			continue
		}

		info, err := r.detector.DetectBinaryInfo(candidate)
		if err != nil {
			log.Debugf("Failed to detect info for %s: %v", candidate, err)
			continue
		}

		binaryInfos = append(binaryInfos, info)
	}

	return binaryInfos, nil
}

// mergeBuildInfo merges information from provenance and binary detection.
func (r *Rebuilder) mergeBuildInfo(ctx *RebuildContext) {
	if ctx.BuildInfo == nil || len(ctx.BinaryInfo) == 0 {
		return
	}

	buildInfo := ctx.BuildInfo
	binaryInfo := ctx.BinaryInfo[0] // Use first binary as primary source

	// Fill in missing fields from binary detection
	if buildInfo.GoVersion == "" {
		buildInfo.GoVersion = binaryInfo.GoVersion
	}
	if buildInfo.ModulePath == "" {
		buildInfo.ModulePath = binaryInfo.ModulePath
	}

	// Add dependencies from binary
	if buildInfo.Dependencies == nil {
		buildInfo.Dependencies = make(map[string]string)
	}
	for module, version := range binaryInfo.Dependencies {
		if _, exists := buildInfo.Dependencies[module]; !exists {
			buildInfo.Dependencies[module] = version
		}
	}

	// Merge build args
	if buildInfo.BuildArgs == nil {
		buildInfo.BuildArgs = make(map[string]string)
	}
	for key, value := range binaryInfo.BuildSettings {
		if _, exists := buildInfo.BuildArgs[key]; !exists {
			buildInfo.BuildArgs[key] = value
		}
	}

	log.Debug("Merged provenance and binary detection information")
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

// buildBinaryWithUpdates creates a BuildKit LLB state that rebuilds the binary.
func (r *Rebuilder) buildBinaryWithUpdates(
	baseImage string,
	buildInfo *BuildInfo,
	updates map[string]string,
) (llb.State, error) {
	// Start from base image
	state := llb.Image(baseImage)

	// Set working directory
	workdir := buildInfo.Workdir
	if workdir == "" {
		workdir = "/build"
	}
	state = state.Dir(workdir)

	// Copy go.mod and go.sum if we have module info
	if buildInfo.ModulePath != "" {
		// Note: In real implementation, we'd need to extract these from the original image
		// For now, we'll generate them based on detected dependencies
		goMod := r.generateGoMod(buildInfo, updates)
		state = state.File(
			llb.Mkfile("go.mod", 0o644, []byte(goMod)),
		)
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
	for _, flag := range buildInfo.BuildFlags {
		parts = append(parts, flag)
	}

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
	case RebuildStrategyHeuristic:
		return "heuristic"
	case RebuildStrategyNone:
		return "none"
	default:
		return "unknown"
	}
}

// CopyBinaryToTarget copies the rebuilt binary to its target location in the image.
func (r *Rebuilder) CopyBinaryToTarget(
	state llb.State,
	binaryInfo *BinaryInfo,
	buildDir string,
) llb.State {
	// Determine source binary path (where it was built)
	sourcePath := filepath.Join(buildDir, filepath.Base(binaryInfo.Path))

	// Determine target path (where it should be in the final image)
	targetPath := binaryInfo.Path

	// Copy the binary to the target location
	return state.File(
		llb.Copy(state, sourcePath, targetPath),
	)
}
