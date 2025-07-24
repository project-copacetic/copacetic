package types

import (
	"time"
)

// PatchOpts contains parameters common to both patch and generate commands.
type PatchOpts struct {
	// Core image configuration
	Image      string
	ReportFile string
	PatchedTag string
	Suffix     string

	// Working environment
	WorkingFolder string
	Timeout       time.Duration

	// Scanner and output
	Scanner     string
	IgnoreError bool

	// Output configuration
	Format string
	Output string

	// Buildkit connection options
	BkAddr       string
	BkCACertPath string
	BkCertPath   string
	BkKeyPath    string

	// Platform and push
	Push     bool
	Platform []string
	Loader   string

	// Generate specific
	OutputContext string
}
