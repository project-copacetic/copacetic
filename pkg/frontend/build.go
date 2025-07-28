package frontend

import (
	"context"
	"fmt"

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
	if config.Report != "" {
		var parseErr error
		// Use the same approach as pkg/patch
		vr, parseErr = report.TryParseScanReport(config.Report, config.Scanner)
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
	updatedState, patchCommands, err := pm.InstallUpdates(ctx, vr, config.IgnoreError)
	if err != nil {
		if config.IgnoreError {
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
		if config.IgnoreError {
			// Log error but continue with original state
			fmt.Printf("Warning: failed to build patched image (ignored): %v\n", err)
			return bkConfig.ImageState, nil
		}
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
		return "", "", errors.Wrap(err, "failed to parse OS info from os-release")
	}

	return osInfo.Type, osInfo.Version, nil
}
