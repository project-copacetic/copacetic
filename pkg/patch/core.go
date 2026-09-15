package patch

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	copachisel "github.com/project-copacetic/copacetic/pkg/chisel"
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
	ChiselRelease string

	// Optional error channel for patch command integration
	ErrorChannel chan error

	// If true, return the BuildKit state instead of solving it
	ReturnState bool

	// Toolchain patch level (e.g., "patch", "minor", "major"; empty = disabled)
	ToolchainPatchLevel string
	GoVCSURL            string

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
	Annotations      map[string]string

	// BuildKit state and config (only set if ReturnState is true)
	PatchedState *llb.State
	ConfigData   []byte
}

// Context wraps the context and gateway client for core operations.
type Context struct {
	Context context.Context
	Client  gwclient.Client
}

// trySendError safely sends an error to the channel without panicking if closed.
// This is needed because the error channel may be closed during context cancellation
// while goroutines are still attempting to send errors.
func trySendError(ch chan error, err error) {
	if ch == nil {
		return
	}
	defer func() {
		// Recover from "send on closed channel" panic
		_ = recover()
	}()
	// Non-blocking send - if the channel is full or closed, we don't block
	select {
	case ch <- err:
	default:
	}
}

func currentSuppliedImageState(config *buildkit.Config) *llb.State {
	if config.PatchedConfigData != nil {
		return &config.PatchedImageState
	}
	return &config.ImageState
}

func preflightReportForNativeChisel(
	ctx context.Context,
	c gwclient.Client,
	config *buildkit.Config,
	platform *types.PatchPlatform,
	updates *unversioned.UpdateManifest,
) error {
	if updates == nil {
		return nil
	}

	manifestExists, err := common.StateFileExists(
		ctx,
		c,
		currentSuppliedImageState(config),
		&platform.Platform,
		pkgmgr.NativeChiselManifestPath,
	)
	if err != nil {
		return fmt.Errorf("inspect target image for native Chisel metadata: %w", err)
	}
	if manifestExists {
		return errors.New(pkgmgr.NativeChiselTargetedPatchError)
	}
	return nil
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
		trySendError(opts.ErrorChannel, err)
		return nil, err
	}

	if err := preflightReportForNativeChisel(ctx, c, config, opts.TargetPlatform, updates); err != nil {
		trySendError(opts.ErrorChannel, err)
		return nil, err
	}

	// Determine if we need OS-level patching or language-only patching.
	// Language-only mode applies when the report has lang updates but no OS updates
	// (common for scratch/distroless/busybox Go binary images).
	langOnlyMode := updates != nil && len(updates.OSUpdates) == 0 && len(updates.LangUpdates) > 0

	var manager pkgmgr.PackageManager
	var patchedImageState *llb.State
	var errPkgs []string

	if langOnlyMode {
		log.Debug("No OS package updates found; skipping OS package manager setup and proceeding with language updates only.")
		st := config.ImageState
		patchedImageState = &st
	} else {
		// Create package manager helper (requires OS metadata in the report)
		manager, err = setupPackageManager(ctx, c, config, opts)
		if err != nil {
			trySendError(opts.ErrorChannel, err)
			return nil, err
		}

		var installErr error
		patchedImageState, errPkgs, installErr = manager.InstallUpdates(ctx, opts.Updates, opts.IgnoreError)
		if installErr != nil {
			trySendError(opts.ErrorChannel, installErr)
			return nil, installErr
		}
	}

	// For normal Docker export, continue with solving but preserve states
	// Handle Language Specific Updates
	if updates != nil && len(updates.LangUpdates) > 0 {
		languageManagers := langmgr.GetLanguageManagers(config, workingFolder, updates, opts.ToolchainPatchLevel, opts.GoVCSURL, opts.ImageName)
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
					trySendError(opts.ErrorChannel, combinedLangError)
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
			trySendError(opts.ErrorChannel, combinedLangError)
			return nil, combinedLangError
		}
	} else {
		log.Debug("No language-specific updates found in the manifest.")
	}

	// Collect optional package-manager metadata after installation, when values
	// such as resolved release and tool versions are available.
	managerAnnotations := pkgmgr.GetPackageManagerAnnotations(manager)

	// Preserve the state and config for potential OCI export use. Mirror the
	// annotations into image-config labels as well as manifest annotations so
	// frontends and exporters that consume config metadata retain the provenance.
	preservedConfig, err := imageConfigWithAnnotations(config, managerAnnotations)
	if err != nil {
		trySendError(opts.ErrorChannel, err)
		return nil, err
	}
	preservedState, err := preservedImageState(patchedImageState, preservedConfig)
	if err != nil {
		trySendError(opts.ErrorChannel, err)
		return nil, err
	}

	// If ReturnState is true, return the state without solving
	if opts.ReturnState {
		return &Result{
			Result:           nil, // No result when returning state
			PackageType:      packageType(manager),
			ErroredPackages:  errPkgs,
			ValidatedUpdates: getValidatedUpdates(opts.Updates, errPkgs),
			Annotations:      managerAnnotations,
			PatchedState:     preservedState,
			ConfigData:       preservedConfig,
		}, nil
	}

	// Marshal the state for the target platform
	log.Info("Building patched image...")
	def, err := patchedImageState.Marshal(ctx, llb.Platform(opts.TargetPlatform.Platform))
	if err != nil {
		trySendError(opts.ErrorChannel, err)
		return nil, fmt.Errorf("unable to get platform from ImageState %w", err)
	}

	// Solve the definition to get the result
	res, err := c.Solve(ctx, gwclient.SolveRequest{
		Definition: def.ToPB(),
		Evaluate:   true,
	})
	if err != nil {
		trySendError(opts.ErrorChannel, err)
		return nil, err
	}

	// Normalize the configuration for the target platform
	fixed, err := normalizeConfigForPlatform(preservedConfig, opts.TargetPlatform)
	if err != nil {
		trySendError(opts.ErrorChannel, err)
		return nil, err
	}
	res.AddMeta(exptypes.ExporterImageConfigKey, fixed)
	addPackageManagerAnnotations(res, managerAnnotations)

	// Return result with BOTH the solved result AND preserved states
	// This enables Docker export (from result) AND OCI layout (from states)
	return &Result{
		Result:           res,
		PackageType:      packageType(manager),
		ErroredPackages:  errPkgs,
		ValidatedUpdates: getValidatedUpdates(opts.Updates, errPkgs),
		Annotations:      managerAnnotations,
		PatchedState:     preservedState,  // Always preserve for OCI export
		ConfigData:       preservedConfig, // Always preserve for OCI export
	}, nil
}

func preservedImageState(state *llb.State, config []byte) (*llb.State, error) {
	preserved, err := state.WithImageConfig(config)
	if err != nil {
		return nil, fmt.Errorf("attach image config to preserved state: %w", err)
	}
	return &preserved, nil
}

// imageConfigWithAnnotations returns the configuration that belongs to the
// image being patched. Repatching starts package operations from the recorded
// base image, but must publish the supplied patched image's configuration.
func imageConfigWithAnnotations(config *buildkit.Config, annotations map[string]string) ([]byte, error) {
	configData := config.ConfigData
	if config.PatchedConfigData != nil {
		merged, err := common.MergeImageRuntimeConfig(config.ConfigData, config.PatchedConfigData)
		if err != nil {
			return nil, err
		}
		configData = merged
	}
	return common.AddImageConfigLabels(configData, annotations)
}

// addPackageManagerAnnotations exposes manager-provided OCI annotations to the exporter.
func addPackageManagerAnnotations(result *gwclient.Result, annotations map[string]string) {
	if result == nil {
		return
	}
	for key, value := range annotations {
		result.AddMeta(exptypes.AnnotationManifestKey(nil, key), []byte(value))
	}
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

// packageType returns the package type string from the manager, or
// "library" when no OS package manager is available (language-only mode).
func packageType(manager pkgmgr.PackageManager) string {
	if manager != nil {
		return manager.GetPackageType()
	}
	return utils.PkgTypeLibrary
}

func explicitNativeChiselOS(
	ctx context.Context,
	c gwclient.Client,
	config *buildkit.Config,
	override string,
) (string, string, bool, error) {
	if override == "" {
		return "", "", false, nil
	}

	manifestExists, err := common.StateFileExists(
		ctx,
		c,
		currentSuppliedImageState(config),
		config.Platform,
		pkgmgr.NativeChiselManifestPath,
	)
	if err != nil {
		return "", "", false, fmt.Errorf("inspect target image for native Chisel metadata at %s: %w", pkgmgr.NativeChiselManifestPath, err)
	}
	if !manifestExists {
		return "", "", false, nil
	}

	release, err := copachisel.ParseRelease(override)
	if err != nil {
		return "", "", false, err
	}
	version := ""
	if release.Kind == copachisel.ReleaseNamed {
		version = strings.TrimPrefix(release.Location, "ubuntu-")
	} else {
		osRelease, exists, err := common.TryExtractOSReleaseFromState(ctx, c, currentSuppliedImageState(config))
		if err != nil {
			return "", "", false, fmt.Errorf("inspect target image OS metadata for explicit Chisel release: %w", err)
		}
		if exists {
			osInfo, err := common.GetOSInfo(ctx, osRelease)
			switch {
			case err != nil:
				log.Warnf("Unable to use target image OS metadata for explicit Chisel release EOL check: %v. Patch attempt will proceed.", err)
			case osInfo.Version == "":
				log.Warn("Target image OS metadata for explicit Chisel release does not contain VERSION_ID; skipping EOL check.")
			default:
				version = osInfo.Version
			}
		}
	}
	return utils.OSTypeUbuntu, version, true, nil
}

// setupPackageManager creates and configures the appropriate package manager
// based on the image's operating system.
func setupPackageManager(ctx context.Context, c gwclient.Client, config *buildkit.Config, opts *Options) (pkgmgr.PackageManager, error) {
	if opts.Updates == nil {
		osType, osVersion, explicitNative, err := explicitNativeChiselOS(ctx, c, config, opts.ChiselRelease)
		if err != nil {
			return nil, err
		}
		if !explicitNative {
			// No vulnerability report provided - detect OS from image.
			fileBytes, extractErr := common.ExtractOSReleaseFromState(ctx, c, &config.ImageState)
			if extractErr != nil {
				return nil, fmt.Errorf("unable to extract /etc/os-release file from state %w", extractErr)
			}

			osInfo, infoErr := common.GetOSInfo(ctx, fileBytes)
			if infoErr != nil {
				return nil, infoErr
			}
			osType = osInfo.Type
			osVersion = osInfo.Version
		}

		// Local and Git release overrides do not encode an Ubuntu version. The
		// native Chisel flow validates and materializes those definitions later,
		// so only run the EOL lookup when a concrete version is available.
		if osVersion != "" {
			isEOL, eolDate, checkErr := utils.CheckEOSL(osType, osVersion)
			if checkErr != nil {
				log.Warnf("Failed to check EOL status for %s %s: %v. Patch attempt will proceed.", osType, osVersion, checkErr)
			} else if isEOL {
				eolMsg := fmt.Sprintf("The operating system %s %s appears to be End-of-Support-Life.", osType, osVersion)
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
		}

		return pkgmgr.GetPackageManagerWithOptions(osType, osVersion, config, opts.WorkingFolder, pkgmgr.PackageManagerOptions{
			ChiselRelease: opts.ChiselRelease,
		})
	}

	// Use OS information from the vulnerability report
	if opts.Updates.Metadata.OS.Type == "" || opts.Updates.Metadata.OS.Version == "" {
		return nil, fmt.Errorf("vulnerability report metadata is incomplete: OS type=%q, version=%q", opts.Updates.Metadata.OS.Type, opts.Updates.Metadata.OS.Version)
	}
	return pkgmgr.GetPackageManagerWithOptions(opts.Updates.Metadata.OS.Type, opts.Updates.Metadata.OS.Version, config, opts.WorkingFolder, pkgmgr.PackageManagerOptions{
		ChiselRelease: opts.ChiselRelease,
	})
}
