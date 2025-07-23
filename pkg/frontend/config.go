package frontend

import (
	"context"
	"fmt"
	"strings"

	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/pkg/errors"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// FrontendConfig holds the parsed configuration for the frontend
type FrontendConfig struct {
	// Base image reference to patch
	BaseImage string

	// Vulnerability report data
	Report []byte

	// Scanner type (e.g., trivy, grype)
	Scanner string

	// Platform to patch (if multi-platform)
	Platform *ispec.Platform

	// Whether to ignore errors during patching
	IgnoreErrors bool

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

// ParseConfig parses the frontend options from the build context
func ParseConfig(ctx context.Context, client gwclient.Client) (*FrontendConfig, error) {
	opts := client.BuildOpts()

	config := &FrontendConfig{
		Scanner:     "trivy", // default scanner
		Annotations: make(map[string]string),
	}

	// Parse base image
	if v, ok := opts.Opts[keyImage]; ok {
		config.BaseImage = v
	} else {
		return nil, errors.New("base image reference required via --opt image=<ref>")
	}

	// Parse scanner type
	if v, ok := opts.Opts[keyScanner]; ok {
		config.Scanner = v
	}

	// Parse ignore errors flag
	if v, ok := opts.Opts[keyIgnoreErrors]; ok {
		config.IgnoreErrors = v == "true" || v == "1"
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
	if reportData, ok := opts.Opts[keyReport]; ok {
		// Inline report data
		config.Report = []byte(reportData)
	} else if reportPath, ok := opts.Opts[keyReportPath]; ok {
		// Read report from build context
		report, err := readReportFromContext(ctx, client, reportPath)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read report from context: %s", reportPath)
		}
		config.Report = report
	} else {
		return nil, errors.New("vulnerability report required via --opt report=<data> or --opt report-path=<path>")
	}

	// Parse package manager
	if v, ok := opts.Opts[keyPkgMgr]; ok {
		config.PkgMgr = v
	}

	// Parse offline mode
	if v, ok := opts.Opts[keyOfflineMode]; ok {
		config.OfflineMode = v == "true" || v == "1"
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

// parsePlatform parses a platform string (e.g., "linux/amd64", "linux/arm64/v8")
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

// readReportFromContext reads a file from the build context
func readReportFromContext(ctx context.Context, client gwclient.Client, path string) ([]byte, error) {
	// TODO: Implement reading from build context
	// For now, this is a placeholder that returns an error
	return nil, fmt.Errorf("reading from build context not yet implemented - use --opt report=<inline-data> instead")
}