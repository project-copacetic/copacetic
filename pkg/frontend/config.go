package frontend

import (
	"context"
	"fmt"
	"os"
	"strings"

	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/project-copacetic/copacetic/pkg/types"
)

const (
	trueStr = "true"
)

// Config holds the parsed configuration for the frontend.
// It extends the common PatchOpts with frontend-specific settings.
type Config struct {
	// Embed common patch options
	*types.Options

	// Frontend-specific options
	Platform *ispec.Platform

	// Package manager type (auto-detected if not specified)
	PkgMgr string

	// Whether to run in offline mode (air-gapped environments)
	OfflineMode bool

	// Cache mode for BuildKit operations
	CacheMode string

	// Security mode constraints
	SecurityMode string

	// Package mirror for air-gapped environments
	PackageMirror string

	// Additional annotations to add to patched image
	Annotations map[string]string
}

// ParseConfig parses the frontend options from the build context.
func ParseConfig(ctx context.Context, client gwclient.Client) (*Config, error) {
	opts := client.BuildOpts()

	config := &Config{
		Options: &types.Options{
			Scanner: "trivy", // default scanner
		},
		Annotations: make(map[string]string),
	}

	// Parse base image
	if v, ok := opts.Opts[keyImage]; ok {
		config.Image = v
	} else {
		return nil, errors.New("base image reference required via --opt image=<ref>")
	}

	// Parse scanner type
	if v, ok := opts.Opts[keyScanner]; ok {
		config.Scanner = v
	}

	// Parse ignore errors flag
	if v, ok := opts.Opts[keyIgnoreErrors]; ok {
		config.IgnoreError = v == trueStr || v == "1"
	}

	// Parse platform
	if v, ok := opts.Opts[keyPlatform]; ok {
		p, err := parsePlatform(v)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid platform: %s", v)
		}
		config.Platform = p
	}

	// Parse vulnerability report
	if reportPath, ok := opts.Opts[keyReport]; ok {
		// Direct file path - same as patch command --report/-r
		config.Report = reportPath
	} else if reportPath, ok := opts.Opts[keyReportPath]; ok {
		// Read report from build context and save to persistent location
		reportData, err := readReportFromContext(ctx, client, reportPath)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read report from context: %s", reportPath)
		}
		tempFile, err := saveReportToTempFile(reportData)
		if err != nil {
			return nil, errors.Wrap(err, "failed to save report to temp file")
		}
		config.Report = tempFile
	} else if updateAll, ok := opts.Opts["update-all"]; ok && (updateAll == trueStr || updateAll == "1") {
		// Update all mode - no report needed
		config.Report = ""
	} else {
		return nil, errors.New("vulnerability report required via --opt report=<file-path> or --opt report-path=<build-context-path>, or --opt update-all=true")
	}

	// Parse package manager
	if v, ok := opts.Opts[keyPkgMgr]; ok {
		config.PkgMgr = v
	}

	// Parse offline mode
	if v, ok := opts.Opts[keyOfflineMode]; ok {
		config.OfflineMode = v == trueStr || v == "1"
	}

	// Parse cache mode
	if v, ok := opts.Opts[keyCacheMode]; ok {
		config.CacheMode = v
	}

	// Parse security mode
	if v, ok := opts.Opts[keySecurityMode]; ok {
		config.SecurityMode = v
	}

	// Parse package mirror
	if v, ok := opts.Opts[keyMirror]; ok {
		config.PackageMirror = v
	}

	// Parse additional annotations
	for k, v := range opts.Opts {
		if strings.HasPrefix(k, "annotation.") {
			annotKey := strings.TrimPrefix(k, "annotation.")
			config.Annotations[annotKey] = v
		}
	}

	return config, nil
}

// saveReportToTempFile saves report data to a temporary file and returns the file path.
// This matches the pkg/patch approach of working with file paths.
func saveReportToTempFile(data []byte) (string, error) {
	tempFile, err := os.CreateTemp("", "copa-report-*.json")
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp file")
	}
	defer tempFile.Close()

	if _, err := tempFile.Write(data); err != nil {
		os.Remove(tempFile.Name())
		return "", errors.Wrap(err, "failed to write report data to temp file")
	}

	return tempFile.Name(), nil
}

// parsePlatform parses a platform string (e.g., "linux/amd64", "linux/arm64/v8").
func parsePlatform(p string) (*ispec.Platform, error) {
	parts := strings.Split(p, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid platform format: %s", p)
	}

	platform := &ispec.Platform{
		OS:           parts[0],
		Architecture: parts[1],
	}

	if len(parts) > 2 {
		platform.Variant = parts[2]
	}

	return platform, nil
}

// readReportFromContext reads a file from the build context.
func readReportFromContext(ctx context.Context, client gwclient.Client, path string) ([]byte, error) {
	// Get the build context inputs
	inputs, err := client.Inputs(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get build inputs")
	}

	// Look for the context input (usually named "context")
	contextState, ok := inputs["context"]
	if !ok {
		// Debug: Print all available inputs
		var availableInputs []string
		for name := range inputs {
			availableInputs = append(availableInputs, name)
		}
		return nil, errors.Errorf("build context not found in inputs, available inputs: %v", availableInputs)
	}

	// Solve the context state to get a reference
	def, err := contextState.Marshal(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal context state")
	}

	res, err := client.Solve(ctx, gwclient.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to solve context state")
	}

	ref, err := res.SingleRef()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get context reference")
	}

	// Read the file from the build context
	data, err := ref.ReadFile(ctx, gwclient.ReadRequest{
		Filename: path,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read file: %s", path)
	}

	return data, nil
}
