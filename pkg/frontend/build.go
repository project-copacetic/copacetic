package frontend

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/pkg/errors"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

// BuildPatchedImage builds a patched image using the Copa patching logic.
func (f *Frontend) buildPatchedImage(ctx context.Context, config *Config) (llb.State, error) {
	// Initialize buildkit configuration
	bkConfig, err := buildkit.InitializeBuildkitConfig(ctx, f.client, config.Image, config.Platform)
	if err != nil {
		return llb.State{}, errors.Wrap(err, "failed to initialize buildkit config")
	}

	// Parse the vulnerability report (or use nil for update all mode)
	var vr *unversioned.UpdateManifest
	if config.ReportFile != "" {
		var parseErr error
		// Use the same approach as pkg/patch
		vr, parseErr = report.TryParseScanReport(config.ReportFile, config.Scanner)
		if parseErr != nil {
			return llb.State{}, errors.Wrap(parseErr, "failed to parse vulnerability report")
		}
	}
	// If config.ReportFile is empty, vr will be nil, which triggers "update all" mode in package managers

	// Get the OS information from the report metadata or detect from image
	var osType, osVersion string
	if vr != nil && vr.Metadata.OS.Type != "" {
		osType = vr.Metadata.OS.Type
		osVersion = vr.Metadata.OS.Version
	}

	// If no OS info from report (including update-all mode), detect from image
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

	// Check if there are packages to update (skip for update-all mode)
	if vr != nil && len(vr.Updates) == 0 {
		// No packages to update, return original image
		return bkConfig.ImageState, nil
	}

	// Apply package updates using existing Copa logic
	updatedState, patchCommands, err := pm.InstallUpdates(ctx, vr, config.IgnoreErrors)
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
	finalState, err := graphBuilder.BuildPatchedImage(ctx, updatedState, patchCommands)
	if err != nil {
		return llb.State{}, errors.Wrap(err, "failed to build patched image")
	}

	return finalState, nil
}

// detectOSFromImage attempts to detect the OS type and version from the image.
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

	// Use the robust OS detection from pkg/common
	osInfo, err := common.GetOSInfo(ctx, osReleaseData)
	if err != nil {
		// Fallback to parsing manually if common.GetOSInfo fails
		osType, osVersion := parseOSRelease(string(osReleaseData))
		return osType, osVersion, nil
	}

	return osInfo.Type, osInfo.Version, nil
}

// parseOSRelease parses /etc/os-release content to extract OS info.
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

// parseReportData parses vulnerability report data from bytes.
func (f *Frontend) parseReportData(data []byte, scannerName string) (*unversioned.UpdateManifest, error) {
	// Create a temporary file to work with the existing report parsing infrastructure
	tempFile, err := f.createTempReportFile(data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create temporary report file")
	}
	defer os.Remove(tempFile) // Clean up temp file

	// Use the existing pkg/report infrastructure for parsing
	manifest, err := report.TryParseScanReport(tempFile, scannerName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse %s report", scannerName)
	}

	return manifest, nil
}

// createTempReportFile creates a temporary file with the report data for use with pkg/report.
func (f *Frontend) createTempReportFile(data []byte) (string, error) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "copa-report-*.json")
	if err != nil {
		return "", errors.Wrap(err, "failed to create temporary file")
	}
	defer tmpFile.Close()

	// Write the report data to the file
	if _, err := tmpFile.Write(data); err != nil {
		os.Remove(tmpFile.Name()) // Clean up on error
		return "", errors.Wrap(err, "failed to write report data to temporary file")
	}

	return tmpFile.Name(), nil
}
