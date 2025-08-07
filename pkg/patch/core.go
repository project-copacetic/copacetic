package patch

import (
	"context"
	"fmt"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

// Options contains the parameters needed for the core patching logic.
type Options struct {
	// Image and platform information
	ImageName      string
	TargetPlatform *types.PatchPlatform

	// Update information
	Updates *unversioned.UpdateManifest

	// Working environment
	WorkingFolder string
	IgnoreError   bool

	// Optional error channel for patch command integration
	ErrorChannel chan error
}

// Result contains the result of the core patching operation.
type Result struct {
	// BuildKit gateway result
	Result *gwclient.Result

	// Package manager information
	PackageType      string
	ErroredPackages  []string
	ValidatedUpdates []unversioned.UpdatePackage
}

// Context wraps the context and gateway client for core operations.
type Context struct {
	Context context.Context
	Client  gwclient.Client
}

// ExecutePatchCore executes the core patching logic that can be used by both
// the patch command and a buildkit frontend.
func ExecutePatchCore(patchCtx *Context, opts *Options) (*Result, error) {
	ctx := patchCtx.Context
	c := patchCtx.Client

	// Configure buildctl/client for use by package manager
	config, err := buildkit.InitializeBuildkitConfig(ctx, c, opts.ImageName, &opts.TargetPlatform.Platform)
	if err != nil {
		if opts.ErrorChannel != nil {
			opts.ErrorChannel <- err
		}
		return nil, err
	}

	// Create package manager helper
	manager, err := setupPackageManager(ctx, c, config, opts)
	if err != nil {
		if opts.ErrorChannel != nil {
			opts.ErrorChannel <- err
		}
		return nil, err
	}

	// Apply patches and get the patched image state
	patchedImageState, errPkgs, err := manager.InstallUpdates(ctx, opts.Updates, opts.IgnoreError)
	if err != nil {
		if opts.ErrorChannel != nil {
			opts.ErrorChannel <- err
		}
		return nil, err
	}

	// Marshal the state for the target platform
	def, err := patchedImageState.Marshal(ctx, llb.Platform(opts.TargetPlatform.Platform))
	if err != nil {
		if opts.ErrorChannel != nil {
			opts.ErrorChannel <- err
		}
		return nil, fmt.Errorf("unable to get platform from ImageState %w", err)
	}

	// Solve the definition to get the result
	res, err := c.Solve(ctx, gwclient.SolveRequest{
		Definition: def.ToPB(),
		Evaluate:   true,
	})
	if err != nil {
		if opts.ErrorChannel != nil {
			opts.ErrorChannel <- err
		}
		return nil, err
	}

	// Normalize the configuration for the target platform
	fixed, err := normalizeConfigForPlatform(config.ConfigData, opts.TargetPlatform)
	if err != nil {
		if opts.ErrorChannel != nil {
			opts.ErrorChannel <- err
		}
		return nil, err
	}
	res.AddMeta(exptypes.ExporterImageConfigKey, fixed)

	// Prepare the validated updates (excluding errored packages)
	var validatedUpdates []unversioned.UpdatePackage
	if opts.Updates != nil {
		for _, update := range opts.Updates.Updates {
			if !slices.Contains(errPkgs, update.Name) {
				validatedUpdates = append(validatedUpdates, update)
			}
		}
	}

	return &Result{
		Result:           res,
		PackageType:      manager.GetPackageType(),
		ErroredPackages:  errPkgs,
		ValidatedUpdates: validatedUpdates,
	}, nil
}

// setupPackageManager creates and configures the appropriate package manager
// based on the image's operating system.
func setupPackageManager(ctx context.Context, c gwclient.Client, config *buildkit.Config, opts *Options) (pkgmgr.PackageManager, error) {
	if opts.Updates == nil {
		// No vulnerability report provided - detect OS from image
		fileBytes, err := buildkit.ExtractFileFromState(ctx, c, &config.ImageState, "/etc/os-release")
		if err != nil {
			return nil, fmt.Errorf("unable to extract /etc/os-release file from state %w", err)
		}

		osInfo, err := common.GetOSInfo(ctx, fileBytes)
		if err != nil {
			return nil, err
		}

		osType := osInfo.Type
		osVersion := osInfo.Version

		// Check for end-of-life status
		isEOL, eolDate, err := utils.CheckEOSL(osType, osVersion)
		if err != nil {
			log.Warnf("Failed to check EOL status for %s %s: %v. Patch attempt will proceed.", osType, osVersion, err)
		} else if isEOL {
			eolMsg := fmt.Sprintf("The operating system %s %s appears to be End-Of-Support-Life.", osType, osVersion)
			if eolDate != "Unknown" && eolDate != "Not in EOL DB" && eolDate != "Normalization Failed" && eolDate != "API Rate Limited" {
				eolMsg += fmt.Sprintf(" (EOL date: %s)", eolDate)
			}
			eolMsg += " Patching may fail, be incomplete, or use archived repositories. Consider upgrading the base image."
			log.Warn(eolMsg)
		}

		// Get package manager based on detected OS
		return pkgmgr.GetPackageManager(osType, osVersion, config, opts.WorkingFolder)
	}

	// Use OS information from the vulnerability report
	return pkgmgr.GetPackageManager(opts.Updates.Metadata.OS.Type, opts.Updates.Metadata.OS.Version, config, opts.WorkingFolder)
}
