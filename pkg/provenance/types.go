package provenance

// RebuildStrategy defines how Copa should attempt to rebuild Go binaries.
type RebuildStrategy int

const (
	// RebuildStrategyAuto automatically chooses the best strategy based on available information.
	RebuildStrategyAuto RebuildStrategy = iota
	// RebuildStrategyHeuristic uses detected binary information for rebuild.
	RebuildStrategyHeuristic
	// RebuildStrategyNone indicates no rebuild is possible.
	RebuildStrategyNone
)

// BuildInfo contains information extracted about how a Go binary was built.
type BuildInfo struct {
	// BuildArgs contains the build arguments used.
	BuildArgs map[string]string
	// GoVersion is the Go version used for building.
	GoVersion string
	// BaseImage is the base image reference used.
	BaseImage string
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
	// Dependencies maps module names to versions (from binary detection).
	Dependencies map[string]string
}

// BinaryInfo contains information extracted from a Go binary using `go version -m`.
type BinaryInfo struct {
	// Path is the filesystem path to the binary in the target image.
	Path string
	// GoVersion is the Go version used to build the binary (e.g., "go1.21.5").
	GoVersion string
	// ModulePath is the main module path (e.g., "github.com/example/app").
	ModulePath string
	// Main is the main module info (path and version).
	Main string
	// Dependencies maps module names to versions.
	Dependencies map[string]string
	// BuildSettings contains build settings (CGO_ENABLED, GOOS, GOARCH, ldflags, etc.).
	BuildSettings map[string]string
	// VCS contains version control info (vcs, vcs.revision, vcs.time, vcs.modified).
	VCS map[string]string
}

// RebuildContext contains all information needed for a binary rebuild attempt.
type RebuildContext struct {
	// Strategy is the rebuild strategy to use.
	Strategy RebuildStrategy
	// BuildInfo is information extracted from binary detection.
	BuildInfo *BuildInfo
	// BinaryInfo contains information from detected Go binaries.
	BinaryInfo []*BinaryInfo
}

// RebuildResult contains the outcome of a rebuild attempt.
type RebuildResult struct {
	// Success indicates if the rebuild was successful.
	Success bool
	// Strategy is the strategy that was used.
	Strategy string
	// Error is the error if rebuild failed.
	Error error
	// Warnings are non-fatal issues encountered.
	Warnings []string
	// BinariesRebuilt is the number of binaries successfully rebuilt.
	BinariesRebuilt int
	// RebuiltBinaries maps original binary paths to their rebuild status.
	RebuiltBinaries map[string]bool
}
