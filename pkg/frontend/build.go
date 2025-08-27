package frontend

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/util/bklog"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

// BuildPatchedImage builds a patched image using the Copa patching logic.
// This reuses the same components as the CLI to ensure consistency.
func (f *Frontend) buildPatchedImage(ctx context.Context, opts *types.Options, platform *ocispecs.Platform) (llb.State, error) {
	// Create progress group for the overall patching process
	patchGroup := llb.ProgressGroup("copa-patch", "Installing security updates", false)
	
	// Initialize buildkit configuration with the frontend client
	var imageState llb.State
	if platform != nil {
		// Platform-specific image
		imageState = llb.Image(opts.Image, llb.Platform(*platform), llb.WithCustomName("Loading base image"), patchGroup)
	} else {
		// Default platform
		imageState = llb.Image(opts.Image, llb.WithCustomName("Loading base image"), patchGroup)
	}

	bkConfig := &buildkit.Config{
		Client:     f.client,
		ImageState: imageState,
	}

	// Parse the vulnerability report if provided
	var vr *unversioned.UpdateManifest
	if opts.Report != "" {
		reportPath := opts.Report

		// If report is a directory and we have a platform, look for platform-specific report
		if platform != nil {
			if fi, err := os.Stat(opts.Report); err == nil && fi.IsDir() {
				// Build platform-specific filename
				platformFile := fmt.Sprintf("%s-%s", platform.OS, platform.Architecture)
				if platform.Variant != "" {
					platformFile = fmt.Sprintf("%s-%s", platformFile, platform.Variant)
				}
				platformFile += ".json"

				reportPath = filepath.Join(opts.Report, platformFile)

				// Check if platform-specific report exists
				if _, err := os.Stat(reportPath); os.IsNotExist(err) {
					bklog.G(ctx).WithField("component", "copa-frontend").WithField("platform", platformFile).Warn("No report found for platform")
					// Return original image if no report for this platform
					return bkConfig.ImageState, nil
				}
			}
		}

		var err error
		vr, err = report.TryParseScanReport(reportPath, opts.Scanner)
		if err != nil {
			return llb.State{}, errors.Wrap(err, "failed to parse vulnerability report")
		}
	}

	// Detect OS from the image
	osType, osVersion, err := f.detectOSFromImage(ctx, &bkConfig.ImageState, patchGroup)
	if err != nil {
		return llb.State{}, errors.Wrap(err, "failed to detect OS from image")
	}

	// Create package manager instance
	pm, err := pkgmgr.GetPackageManager(osType, osVersion, bkConfig, "/tmp/copa-work")
	if err != nil {
		return llb.State{}, errors.Wrap(err, "failed to create package manager")
	}

	// Check if there are packages to update
	if vr != nil && len(vr.Updates) == 0 {
		bklog.G(ctx).WithField("component", "copa-frontend").Info("No packages to update, returning original image")
		return bkConfig.ImageState, nil
	}

	// Apply package updates using the same logic as CLI
	patchedState, _, err := pm.InstallUpdates(ctx, vr, opts.IgnoreError)
	if err != nil {
		if opts.IgnoreError {
			bklog.G(ctx).WithError(err).WithField("component", "copa-frontend").Warn("Failed to install updates (ignored)")
			return bkConfig.ImageState, nil
		}
		return llb.State{}, errors.Wrap(err, "failed to install package updates")
	}

	return *patchedState, nil
}

// detectOSFromImage detects the OS type and version from an image state.
func (f *Frontend) detectOSFromImage(ctx context.Context, imageState *llb.State, patchGroup llb.ConstraintsOpt) (string, string, error) {
	if imageState == nil {
		return "", "", errors.New("image state is nil")
	}
	// Create a temporary state to read os-release
	osReleaseState := imageState.File(
		llb.Copy(imageState, "/etc/os-release", "/tmp/os-release", &llb.CopyInfo{
			CreateDestPath: true,
		}),
		llb.WithCustomName("Detecting OS and packages"), patchGroup,
	)

	// Marshal and solve to read the file
	def, err := osReleaseState.Marshal(ctx)
	if err != nil {
		return "", "", err
	}

	res, err := f.client.Solve(ctx, gwclient.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		// If os-release doesn't exist, default to linux
		return "linux", "", nil
	}

	ref, err := res.SingleRef()
	if err != nil {
		return "", "", err
	}

	osReleaseData, err := ref.ReadFile(ctx, gwclient.ReadRequest{
		Filename: "/tmp/os-release",
	})
	if err != nil {
		return "linux", "", nil
	}

	// Use the common OS detection logic
	osInfo, err := common.GetOSInfo(ctx, osReleaseData)
	if err != nil {
		return "", "", errors.Wrap(err, "failed to parse OS info")
	}

	return osInfo.Type, osInfo.Version, nil
}
