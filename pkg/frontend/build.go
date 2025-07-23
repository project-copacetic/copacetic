package frontend

import (
	"context"
	"fmt"
	"strings"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/pkg/errors"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

// BuildPatchedImage builds a patched image using the Copa patching logic
func (f *Frontend) buildPatchedImage(ctx context.Context, config *FrontendConfig) (llb.State, error) {
	// Initialize buildkit configuration
	bkConfig, err := buildkit.InitializeBuildkitConfig(ctx, f.client, config.BaseImage, config.Platform)
	if err != nil {
		return llb.State{}, errors.Wrap(err, "failed to initialize buildkit config")
	}

	// Parse the vulnerability report
	vr, err := f.parseReportData(config.Report, config.Scanner)
	if err != nil {
		return llb.State{}, errors.Wrap(err, "failed to parse vulnerability report")
	}

	// Get the OS information from the report metadata
	var osType, osVersion string
	osType = vr.Metadata.OS.Type
	osVersion = vr.Metadata.OS.Version

	// If no OS info in report, try to detect from image
	if osType == "" {
		osType, osVersion, err = f.detectOSFromImage(ctx, bkConfig)
		if err != nil {
			return llb.State{}, errors.Wrap(err, "failed to detect OS from image")
		}
	}

	// Create package manager instance
	pm, err := pkgmgr.GetPackageManager(osType, osVersion, bkConfig, "/tmp/copa-work")
	if err != nil {
		return llb.State{}, errors.Wrap(err, "failed to create package manager")
	}

	// Check if there are packages to update
	if len(vr.Updates) == 0 {
		// No packages to update, return original image
		return bkConfig.ImageState, nil
	}

	// Apply package updates using existing Copa logic
	updatedState, _, err := pm.InstallUpdates(ctx, vr, config.IgnoreErrors)
	if err != nil {
		if config.IgnoreErrors {
			// Log error but continue with original state
			fmt.Printf("Warning: failed to install updates (ignored): %v\n", err)
			return bkConfig.ImageState, nil
		}
		return llb.State{}, errors.Wrap(err, "failed to install package updates")
	}

	// Use enhanced LLB graph construction for better layer management
	graphBuilder := NewLLBGraphBuilder(f.client, config)
	finalState := *updatedState
	
	// Apply any additional LLB enhancements (security constraints, caching, etc.)
	if config.SecurityMode != "" {
		finalState = graphBuilder.applySecurityConstraints(finalState)
	}
	if config.CacheMode != "" {
		finalState = graphBuilder.applyCaching(finalState)
	}

	return finalState, nil
}

// detectOSFromImage attempts to detect the OS type and version from the image
func (f *Frontend) detectOSFromImage(ctx context.Context, bkConfig *buildkit.Config) (string, string, error) {
	// Try to read /etc/os-release from the image
	osReleaseState := bkConfig.ImageState.File(
		llb.Copy(bkConfig.ImageState, "/etc/os-release", "/tmp/os-release", &llb.CopyInfo{
			CreateDestPath: true,
		}),
	)

	def, err := osReleaseState.Marshal(ctx)
	if err != nil {
		return "", "", err
	}

	res, err := f.client.Solve(ctx, gwclient.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		return "", "", err
	}

	ref, err := res.SingleRef()
	if err != nil {
		return "", "", err
	}

	osReleaseData, err := ref.ReadFile(ctx, gwclient.ReadRequest{
		Filename: "/tmp/os-release",
	})
	if err != nil {
		// Fallback to common defaults
		return "linux", "", nil
	}

	// Parse os-release file to extract OS type and version
	osType, osVersion := parseOSRelease(string(osReleaseData))
	return osType, osVersion, nil
}

// parseOSRelease parses /etc/os-release content to extract OS info
func parseOSRelease(content string) (string, string) {
	lines := strings.Split(content, "\n")
	var id, version string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}

	return id, version
}



// parseReportData parses vulnerability report data from bytes
func (f *Frontend) parseReportData(data []byte, scannerName string) (*unversioned.UpdateManifest, error) {
	// Use scanner abstraction for report parsing
	scanner, err := f.scannerFactory.GetScanner(scannerName)
	if err != nil {
		return nil, errors.Wrapf(err, "unsupported scanner: %s", scannerName)
	}
	
	manifest, err := scanner.ParseReport(data)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse %s report", scannerName)
	}
	
	return manifest, nil
}