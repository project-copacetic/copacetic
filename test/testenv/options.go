package testenv

import "github.com/moby/buildkit/client"

// TestRunnerConfig holds configuration for test execution.
type TestRunnerConfig struct {
	// SolveOpts are the options passed to the BuildKit solve operation.
	SolveOpts client.SolveOpt

	// SkipExport skips image export (useful for inspection-only tests).
	// When true, SolveOpts.Exports will be set to nil.
	SkipExport bool
}

// TestRunnerOpt is a functional option for configuring test runs.
type TestRunnerOpt func(*TestRunnerConfig)

// WithSolveOpts sets custom solve options for the test.
// This allows tests to configure exports, cache options, etc.
func WithSolveOpts(opts *client.SolveOpt) TestRunnerOpt {
	return func(cfg *TestRunnerConfig) {
		if opts != nil {
			cfg.SolveOpts = *opts
		}
	}
}

// WithSkipExport skips image export for the test.
// This is useful for tests that only need to inspect the built state
// without exporting to a registry or tarball.
func WithSkipExport() TestRunnerOpt {
	return func(cfg *TestRunnerConfig) {
		cfg.SkipExport = true
	}
}

// WithExportToOCI configures the test to export to an OCI layout directory.
// This is useful for tests that need to inspect the final image layers.
func WithExportToOCI(outputDir string) TestRunnerOpt {
	return func(cfg *TestRunnerConfig) {
		cfg.SolveOpts.Exports = []client.ExportEntry{
			{
				Type:      client.ExporterOCI,
				OutputDir: outputDir,
			},
		}
	}
}

// WithExportToTar configures the test to export to a tarball.
func WithExportToTar(outputPath string) TestRunnerOpt {
	return func(cfg *TestRunnerConfig) {
		cfg.SolveOpts.Exports = []client.ExportEntry{
			{
				Type: client.ExporterTar,
				Attrs: map[string]string{
					"dest": outputPath,
				},
			},
		}
	}
}

// WithExportToImage configures the test to export to a container image.
func WithExportToImage(imageName string, push bool) TestRunnerOpt {
	return func(cfg *TestRunnerConfig) {
		attrs := map[string]string{
			"name": imageName,
		}
		if push {
			attrs["push"] = "true"
		}
		cfg.SolveOpts.Exports = []client.ExportEntry{
			{
				Type:  client.ExporterImage,
				Attrs: attrs,
			},
		}
	}
}
