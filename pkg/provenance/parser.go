package provenance

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Parser extracts build information from SLSA provenance.
type Parser struct{}

// NewParser creates a new provenance parser.
func NewParser() *Parser {
	return &Parser{}
}

// ParseBuildInfo extracts Go-specific build information from SLSA provenance.
func (p *Parser) ParseBuildInfo(attestation *Attestation) (*BuildInfo, error) {
	if attestation == nil || attestation.Predicate == nil {
		return nil, fmt.Errorf("nil attestation or predicate")
	}

	buildInfo := &BuildInfo{
		BuildArgs: make(map[string]string),
	}

	// Try to extract information based on SLSA version
	switch {
	case strings.Contains(attestation.PredicateType, "/v1"):
		return p.parseV1Provenance(attestation.Predicate, buildInfo)
	case strings.Contains(attestation.PredicateType, "/v0.2"):
		return p.parseV02Provenance(attestation.Predicate, buildInfo)
	default:
		return nil, fmt.Errorf("unsupported SLSA provenance version: %s", attestation.PredicateType)
	}
}

// parseV1Provenance parses SLSA v1.0 provenance format.
func (p *Parser) parseV1Provenance(predicate map[string]any, buildInfo *BuildInfo) (*BuildInfo, error) {
	// Extract from buildDefinition
	if buildDef, ok := predicate["buildDefinition"].(map[string]any); ok {
		// Get build type
		if buildType, ok := buildDef["buildType"].(string); ok {
			log.Debugf("Build type: %s", buildType)
		}

		// Extract external parameters (build args, etc.)
		if extParams, ok := buildDef["externalParameters"].(map[string]any); ok {
			p.extractBuildArgs(extParams, buildInfo)
		}

		// Extract resolved dependencies (base images, etc.)
		if deps, ok := buildDef["resolvedDependencies"].([]any); ok {
			p.extractDependencies(deps, buildInfo)
		}
	}

	// Extract from runDetails
	if runDetails, ok := predicate["runDetails"].(map[string]any); ok {
		// Get builder information
		if builder, ok := runDetails["builder"].(map[string]any); ok {
			if id, ok := builder["id"].(string); ok {
				buildInfo.BuilderID = id
			}
		}

		// Extract BuildKit-specific metadata
		if metadata, ok := runDetails["metadata"].(map[string]any); ok {
			p.extractBuildKitMetadata(metadata, buildInfo)
		}
	}

	return p.finalizeBuildInfo(buildInfo), nil
}

// parseV02Provenance parses SLSA v0.2 provenance format.
func (p *Parser) parseV02Provenance(predicate map[string]any, buildInfo *BuildInfo) (*BuildInfo, error) {
	// Extract invocation parameters
	if invocation, ok := predicate["invocation"].(map[string]any); ok {
		if params, ok := invocation["parameters"].(map[string]any); ok {
			p.extractBuildArgs(params, buildInfo)
		}
	}

	// Extract materials (base images, dependencies)
	if materials, ok := predicate["materials"].([]any); ok {
		p.extractDependencies(materials, buildInfo)
	}

	// Extract builder
	if builder, ok := predicate["builder"].(map[string]any); ok {
		if id, ok := builder["id"].(string); ok {
			buildInfo.BuilderID = id
		}
	}

	// Extract BuildKit metadata (v0.2 often has this)
	if metadata, ok := predicate["metadata"].(map[string]any); ok {
		p.extractBuildKitMetadata(metadata, buildInfo)
	}

	return p.finalizeBuildInfo(buildInfo), nil
}

// extractBuildArgs extracts build arguments from parameters.
func (p *Parser) extractBuildArgs(params map[string]any, buildInfo *BuildInfo) {
	for k, v := range params {
		if strVal, ok := v.(string); ok {
			buildInfo.BuildArgs[k] = strVal

			// Look for Go version
			if strings.ToLower(k) == "go_version" || strings.ToLower(k) == "goversion" {
				buildInfo.GoVersion = strVal
			}
		}
	}
}

// extractDependencies extracts base image and dependencies.
func (p *Parser) extractDependencies(deps []any, buildInfo *BuildInfo) {
	for _, dep := range deps {
		depMap, ok := dep.(map[string]any)
		if !ok {
			continue
		}

		uri, hasURI := depMap["uri"].(string)
		if !hasURI {
			continue
		}

		// Check if this is a base image (golang, go, etc.)
		if strings.Contains(uri, "golang") || strings.Contains(uri, "/go:") {
			buildInfo.BaseImage = uri

			// Extract digest if available
			if digest, ok := depMap["digest"].(map[string]any); ok {
				if sha, ok := digest["sha256"].(string); ok {
					buildInfo.BaseImageDigest = "sha256:" + sha
				}
			}

			// Try to extract Go version from image tag
			if buildInfo.GoVersion == "" {
				buildInfo.GoVersion = p.extractGoVersionFromImage(uri)
			}
		}
	}
}

// extractBuildKitMetadata extracts BuildKit-specific metadata including Dockerfile.
func (p *Parser) extractBuildKitMetadata(metadata map[string]any, buildInfo *BuildInfo) {
	// BuildKit stores metadata under a specific key
	buildkitKey := "https://mobyproject.org/buildkit@v1#metadata"
	bkMetadata, ok := metadata[buildkitKey].(map[string]any)
	if !ok {
		return
	}

	// Check provenance mode
	if mode, ok := bkMetadata["mode"].(string); ok {
		buildInfo.ProvenanceMode = mode
		log.Debugf("BuildKit provenance mode: %s", mode)
	}

	// Extract source information (Dockerfile)
	if source, ok := bkMetadata["source"].(map[string]any); ok {
		if infos, ok := source["infos"].([]any); ok {
			for _, info := range infos {
				infoMap, ok := info.(map[string]any)
				if !ok {
					continue
				}

				filename, hasFilename := infoMap["filename"].(string)
				data, hasData := infoMap["data"].(string)

				if hasFilename && hasData && filename == "Dockerfile" {
					// Decode base64 Dockerfile
					decoded, err := base64.StdEncoding.DecodeString(data)
					if err != nil {
						log.Warnf("Failed to decode Dockerfile from provenance: %v", err)
						continue
					}
					buildInfo.Dockerfile = string(decoded)
					log.Debug("Extracted Dockerfile from provenance")

					// Try to extract more info from Dockerfile
					p.analyzeDockerfile(buildInfo.Dockerfile, buildInfo)
				}
			}
		}
	}
}

// analyzeDockerfile attempts to extract build information from a Dockerfile.
func (p *Parser) analyzeDockerfile(dockerfile string, buildInfo *BuildInfo) {
	lines := strings.Split(dockerfile, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// Extract FROM statement
		if strings.HasPrefix(strings.ToUpper(line), "FROM") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				fromImage := parts[1]
				if buildInfo.BaseImage == "" {
					buildInfo.BaseImage = fromImage
				}
				if buildInfo.GoVersion == "" {
					buildInfo.GoVersion = p.extractGoVersionFromImage(fromImage)
				}
			}
		}

		// Look for WORKDIR
		if strings.HasPrefix(strings.ToUpper(line), "WORKDIR") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				buildInfo.Workdir = parts[1]
			}
		}

		// Look for RUN go build commands
		if strings.Contains(strings.ToLower(line), "go build") {
			p.extractBuildCommand(line, buildInfo)
		}
	}
}

// extractBuildCommand extracts go build command details.
func (p *Parser) extractBuildCommand(line string, buildInfo *BuildInfo) {
	buildInfo.BuildCommand = line

	// Check for CGO_ENABLED
	if strings.Contains(line, "CGO_ENABLED=0") {
		buildInfo.CGOEnabled = false
	} else if strings.Contains(line, "CGO_ENABLED=1") {
		buildInfo.CGOEnabled = true
	}

	// Extract common build flags
	if strings.Contains(line, "-trimpath") {
		buildInfo.BuildFlags = append(buildInfo.BuildFlags, "-trimpath")
	}

	// Extract output path and main package
	re := regexp.MustCompile(`-o\s+(\S+)`)
	if matches := re.FindStringSubmatch(line); len(matches) > 1 {
		// Output path found, could help identify main package
		log.Debugf("Found output path: %s", matches[1])
	}

	// Look for main package path
	reMain := regexp.MustCompile(`go build.*\s+(\.\/cmd\/\S+|\./\S+|cmd\/\S+)`)
	if matches := reMain.FindStringSubmatch(line); len(matches) > 1 {
		buildInfo.MainPackage = matches[1]
		log.Debugf("Found main package: %s", buildInfo.MainPackage)
	}
}

// extractGoVersionFromImage attempts to extract Go version from an image reference.
func (p *Parser) extractGoVersionFromImage(imageRef string) string {
	// Pattern: golang:1.21-alpine, golang:1.21.0, go:1.21, etc.
	re := regexp.MustCompile(`(?:golang|go):(\d+\.\d+(?:\.\d+)?)`)
	if matches := re.FindStringSubmatch(imageRef); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// finalizeBuildInfo applies defaults and validates the extracted information.
func (p *Parser) finalizeBuildInfo(buildInfo *BuildInfo) *BuildInfo {
	// Default CGO to disabled if not specified (common for containers)
	if buildInfo.BuildCommand == "" && !buildInfo.CGOEnabled {
		buildInfo.CGOEnabled = false
	}

	// If no explicit build flags and we have a Dockerfile, assume trimpath (common)
	if len(buildInfo.BuildFlags) == 0 && buildInfo.Dockerfile != "" {
		buildInfo.BuildFlags = []string{"-trimpath"}
	}

	return buildInfo
}

// AssessCompleteness evaluates how complete the build information is.
func (p *Parser) AssessCompleteness(buildInfo *BuildInfo) *ProvenanceCompleteness {
	completeness := &ProvenanceCompleteness{
		HasDockerfile:   buildInfo.Dockerfile != "",
		HasBuildCommand: buildInfo.BuildCommand != "",
		HasBaseImage:    buildInfo.BaseImage != "",
		HasGoVersion:    buildInfo.GoVersion != "",
		MissingInfo:     []string{},
	}

	if !completeness.HasDockerfile {
		completeness.MissingInfo = append(completeness.MissingInfo, "Dockerfile")
	}
	if !completeness.HasBuildCommand {
		completeness.MissingInfo = append(completeness.MissingInfo, "build command")
	}
	if !completeness.HasBaseImage {
		completeness.MissingInfo = append(completeness.MissingInfo, "base image")
	}
	if !completeness.HasGoVersion {
		completeness.MissingInfo = append(completeness.MissingInfo, "Go version")
	}

	// Can rebuild if we have at least Go version and base image
	// Dockerfile and build command are helpful but not strictly required
	completeness.CanRebuild = completeness.HasGoVersion && completeness.HasBaseImage

	return completeness
}
