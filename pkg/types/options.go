package types

import (
	"time"

	"github.com/moby/buildkit/util/progress/progressui"
)

// Options contains common copacetic options.
type Options struct {
	// Core single image patch configuration
	Image      string
	Report     string
	PatchedTag string
	Suffix     string

	// Working environment
	WorkingFolder string
	Timeout       time.Duration

	// Scanner and output
	Scanner     string
	IgnoreError bool

	// Output configuration
	Format   string
	Output   string
	Progress progressui.DisplayMode

	// Buildkit connection options
	BkAddr       string
	BkCACertPath string
	BkCertPath   string
	BkKeyPath    string

	// Platform and push
	Push      bool
	Platforms []string
	Loader    string
	OCIDir    string

	// Package types and library patch level
	PkgTypes          string
	LibraryPatchLevel string

	// Generate specific
	OutputContext string

	// EOL configuration
	EOLAPIBaseURL string
	ExitOnEOL     bool
}
