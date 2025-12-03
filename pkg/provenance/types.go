package provenance

import (
	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

// RebuildStrategy defines how Copa should attempt to rebuild Go binaries.
type RebuildStrategy int

const (
	// RebuildStrategyAuto automatically chooses the best strategy based on available information.
	RebuildStrategyAuto RebuildStrategy = iota
	// RebuildStrategyProvenance uses SLSA provenance for rebuild.
	RebuildStrategyProvenance
	// RebuildStrategyHeuristic uses detected binary information for rebuild.
	RebuildStrategyHeuristic
	// RebuildStrategyNone only updates go.mod/go.sum (current default behavior).
	RebuildStrategyNone
)

// Attestation represents a parsed SLSA attestation with provenance information.
type Attestation struct {
	// Statement is the in-toto statement containing the attestation.
	Statement *intoto.Statement
	// Predicate contains the SLSA provenance data (parsed from Statement.Predicate).
	Predicate map[string]any
	// PredicateType is the type of predicate (e.g., "https://slsa.dev/provenance/v1").
	PredicateType string
	// SLSALevel is the inferred SLSA level (0-4).
	SLSALevel int
}

// BuildInfo contains information extracted from SLSA provenance about how a Go binary was built.
type BuildInfo struct {
	// Dockerfile is the base64-decoded Dockerfile from provenance (if available, mode=max only).
	Dockerfile string
	// BuildArgs contains the build arguments used.
	BuildArgs map[string]string
	// GoVersion is the Go version used for building.
	GoVersion string
	// BaseImage is the base image reference used.
	BaseImage string
	// BaseImageDigest is the digest of the base image for verification.
	BaseImageDigest string
	// BuildCommand is the go build command used (if extractable).
	BuildCommand string
	// CGOEnabled indicates if CGO was enabled during the build.
	CGOEnabled bool
	// BuildFlags are additional flags passed to go build.
	BuildFlags []string
	// Workdir is the working directory used during build.
	Workdir string
	// MainPackage is the main package path (e.g., "cmd/app").
	MainPackage string
	// ModulePath is the Go module path (e.g., "github.com/org/repo").
	ModulePath string
	// ProvenanceMode is the BuildKit provenance mode (min/max).
	ProvenanceMode string
	// BuilderID is the builder identity from provenance.
	BuilderID string
	// Dependencies maps module names to versions (from binary detection).
	Dependencies map[string]string
}

// BinaryInfo contains information extracted from a Go binary using buildinfo.
type BinaryInfo struct {
	// Path is the filesystem path to the binary.
	Path string
	// ModulePath is the main module path.
	ModulePath string
	// MainModule is the main module name.
	MainModule string
	// MainModuleVersion is the main module version.
	MainModuleVersion string
	// GoVersion is the Go version used to build the binary.
	GoVersion string
	// Dependencies maps module names to versions.
	Dependencies map[string]string
	// BuildSettings contains build settings (CGO_ENABLED, GOARCH, etc.).
	BuildSettings map[string]string
	// VCSRevision is the VCS commit hash (if available).
	VCSRevision string
	// VCSTime is the VCS commit timestamp (if available).
	VCSTime string
	// VCS is the version control system (git, etc.).
	VCS string
	// VCSModified indicates if the working tree was modified.
	VCSModified bool
	// GOOS is the target operating system.
	GOOS string
	// GOARCH is the target architecture.
	GOARCH string
	// CGOEnabled indicates if CGO was enabled.
	CGOEnabled bool
}

// ProvenanceCompleteness assesses how complete the provenance information is.
type ProvenanceCompleteness struct {
	// HasDockerfile indicates if the Dockerfile is present in provenance.
	HasDockerfile bool
	// HasBuildCommand indicates if build commands can be extracted.
	HasBuildCommand bool
	// HasBaseImage indicates if base image information is available.
	HasBaseImage bool
	// HasGoVersion indicates if Go version is specified.
	HasGoVersion bool
	// CanRebuild is an overall assessment of rebuild feasibility.
	CanRebuild bool
	// MissingInfo lists what information is missing.
	MissingInfo []string
}

// RebuildContext contains all information needed for a binary rebuild attempt.
type RebuildContext struct {
	// Strategy is the rebuild strategy to use.
	Strategy RebuildStrategy
	// Provenance is the SLSA attestation (if available).
	Provenance *Attestation
	// BinaryInfo is information from detected binaries (if available).
	BinaryInfo []*BinaryInfo
	// BuildInfo is information extracted from provenance (if available).
	BuildInfo *BuildInfo
	// Completeness assesses the quality of available information.
	Completeness *ProvenanceCompleteness
}

// RebuildResult contains the outcome of a rebuild attempt.
type RebuildResult struct {
	// Success indicates if the rebuild was successful.
	Success bool
	// Strategy is the strategy that was used.
	Strategy string
	// BinaryPatched indicates if the binary was actually rebuilt.
	BinaryPatched bool
	// GoModUpdated indicates if go.mod/go.sum were updated.
	GoModUpdated bool
	// Error is the error if rebuild failed.
	Error error
	// Warnings are non-fatal issues encountered.
	Warnings []string
	// BinariesRebuilt is the number of binaries successfully rebuilt.
	BinariesRebuilt int
}
