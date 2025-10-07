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
	"github.com/project-copacetic/copacetic/pkg/langmgr"
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
	Updates          *unversioned.UpdateManifest
	ValidatedUpdates *unversioned.UpdateManifest

	// Working environment
	WorkingFolder string
	IgnoreError   bool

	// Optional error channel for patch command integration
	ErrorChannel chan error

	// If true, return the BuildKit state instead of solving it
	ReturnState bool

	// EOL configuration
	ExitOnEOL bool
}

// Result contains the result of the core patching operation.
type Result struct {
	// BuildKit gateway result (nil if ReturnState is true)
	Result *gwclient.Result

	// Package manager information
	PackageType      string
	ErroredPackages  []string
	ValidatedUpdates []unversioned.UpdatePackage

	// BuildKit state and config (only set if ReturnState is true)
	PatchedState *llb.State
	ConfigData   []byte
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
	workingFolder := opts.WorkingFolder
	ignoreError := opts.IgnoreError
	updates := opts.Updates

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

	// For normal Docker export, continue with solving but preserve states
	// Handle Language Specific Updates
	if updates != nil && len(updates.LangUpdates) > 0 {
		languageManagers := langmgr.GetLanguageManagers(config, workingFolder, updates)
		var langErrPkgsFromAllManagers []string
		var combinedLangError error

		currentProcessingState := patchedImageState // Start with the state after OS updates

		for _, individualLangManager := range languageManagers {
			log.Debugf("Applying language updates using manager: %T", individualLangManager)
			var newState *llb.State
			var tempErrPkgs []string
			var tempErr error

			// Call InstallUpdates on the individual language manager instance
			newState, tempErrPkgs, tempErr = individualLangManager.InstallUpdates(ctx, currentProcessingState, updates, ignoreError)

			currentProcessingState = newState // Update state for the next manager or final result

			if tempErr != nil {
				log.Errorf("Error applying updates with language manager %T: %v", individualLangManager, tempErr)
				if combinedLangError == nil {
					combinedLangError = tempErr
				} else {
					combinedLangError = fmt.Errorf("%w; %v", combinedLangError, tempErr)
				}
				if !ignoreError {
					if opts.ErrorChannel != nil {
						opts.ErrorChannel <- combinedLangError
					}
					return nil, combinedLangError
				}
			}
			if len(tempErrPkgs) > 0 {
				langErrPkgsFromAllManagers = append(langErrPkgsFromAllManagers, tempErrPkgs...)
			}
		}

		// Update the main patchedImageState with the result of all language managers
		patchedImageState = currentProcessingState

		// Merge OS-level error packages with language-level error packages
		if len(langErrPkgsFromAllManagers) > 0 {
			errPkgs = append(errPkgs, langErrPkgsFromAllManagers...)
		}

		// Ensure uniqueness of all error packages after processing all language managers
		errPkgs = utils.DeduplicateStringSlice(errPkgs)

		if combinedLangError != nil && !ignoreError {
			if opts.ErrorChannel != nil {
				opts.ErrorChannel <- combinedLangError
			}
			return nil, combinedLangError
		}
	} else {
		log.Debug("No language-specific updates found in the manifest.")
	}

	// Preserve the state and config for potential OCI export use
	// This allows both Docker export AND OCI layout creation from the same patching operation
	preservedState := patchedImageState
	preservedConfig := config.ConfigData

	// If ReturnState is true, return the state without solving
	if opts.ReturnState {
		return &Result{
			Result:           nil, // No result when returning state
			PackageType:      manager.GetPackageType(),
			ErroredPackages:  errPkgs,
			ValidatedUpdates: getValidatedUpdates(opts.Updates, errPkgs),
			PatchedState:     preservedState,
			ConfigData:       preservedConfig,
		}, nil
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

	// Return result with BOTH the solved result AND preserved states
	// This enables Docker export (from result) AND OCI layout (from states)
	return &Result{
		Result:           res,
		PackageType:      manager.GetPackageType(),
		ErroredPackages:  errPkgs,
		ValidatedUpdates: getValidatedUpdates(opts.Updates, errPkgs),
		PatchedState:     preservedState,  // Always preserve for OCI export
		ConfigData:       preservedConfig, // Always preserve for OCI export
	}, nil
}

// getValidatedUpdates extracts validated updates (excluding errored packages).
func getValidatedUpdates(updates *unversioned.UpdateManifest, errPkgs []string) []unversioned.UpdatePackage {
	var validatedUpdates []unversioned.UpdatePackage
	if updates != nil {
		for _, update := range updates.OSUpdates {
			if !slices.Contains(errPkgs, update.Name) {
				validatedUpdates = append(validatedUpdates, update)
			}
		}
	}
	return validatedUpdates
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

			if opts.ExitOnEOL {
				log.Error(eolMsg)
				return nil, fmt.Errorf("exiting due to EOL operating system: %s %s", osType, osVersion)
			}
			log.Warn(eolMsg)
		}

		// Get package manager based on detected OS
		return pkgmgr.GetPackageManager(osType, osVersion, config, opts.WorkingFolder)
	}

	// Use OS information from the vulnerability report
	if opts.Updates.Metadata.OS.Type == "" || opts.Updates.Metadata.OS.Version == "" {
		return nil, fmt.Errorf("vulnerability report metadata is incomplete: OS type=%q, version=%q", opts.Updates.Metadata.OS.Type, opts.Updates.Metadata.OS.Version)
	}
	return pkgmgr.GetPackageManager(opts.Updates.Metadata.OS.Type, opts.Updates.Metadata.OS.Version, config, opts.WorkingFolder)
}
