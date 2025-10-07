package patch

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"strings"
	"time"

	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/imageloader"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/project-copacetic/copacetic/pkg/vex"
)

const (
	copaProduct = "copa"
	defaultTag  = "latest"
	LINUX       = "linux"
)

// removeIfNotDebug removes working folder unless debug mode is enabled.
func removeIfNotDebug(workingFolder string) {
	if log.GetLevel() >= log.DebugLevel {
		// Keep the intermediate outputs for outputs solved to working folder if debugging
		log.Warnf("--debug specified, working folder at %s needs to be manually cleaned up", workingFolder)
	} else {
		os.RemoveAll(workingFolder)
	}
}

// patchSingleArchImage patches a single architecture image.
func patchSingleArchImage(
	ctx context.Context,
	ch chan error,
	opts *types.Options,
	//nolint:gocritic
	targetPlatform types.PatchPlatform,
	multiPlatform bool,
) (*types.PatchResult, error) {
	// Extract options
	image := opts.Image
	reportFile := opts.Report
	patchedTag := opts.PatchedTag
	suffix := opts.Suffix
	workingFolder := opts.WorkingFolder
	scanner := opts.Scanner
	format := opts.Format
	output := opts.Output
	loader := opts.Loader
	ignoreError := opts.IgnoreError
	push := opts.Push
	bkOpts := buildkit.Opts{
		Addr:       opts.BkAddr,
		CACertPath: opts.BkCACertPath,
		CertPath:   opts.BkCertPath,
		KeyPath:    opts.BkKeyPath,
	}
	pkgTypes := opts.PkgTypes
	libraryPatchLevel := opts.LibraryPatchLevel

	if reportFile == "" && output != "" {
		log.Warn("No vulnerability report was provided, so no VEX output will be generated.")
	}

	// if the target platform is different from the host platform, we need to check if emulation is enabled
	// only need to do this check if we're patching a multi-platform image
	if multiPlatform {
		if err := validatePlatformEmulation(targetPlatform); err != nil {
			return nil, err
		}
	}

	// parse the image reference
	imageName, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference: %w", err)
	}

	// resolve final patched tag
	patchImage, patchedTag, err := common.ResolvePatchedImageName(imageName, patchedTag, suffix)
	if err != nil {
		return nil, err
	}
	if multiPlatform {
		patchedTag = archTag(patchedTag, targetPlatform.Architecture, targetPlatform.Variant)
	}
	patchedImageName := fmt.Sprintf("%s:%s", patchImage, patchedTag)
	log.Infof("Patched image name: %s", patchedImageName)

	// Setup working folder
	workingFolder, cleanup, err := setupWorkingFolder(workingFolder)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Parse report for update packages
	var updates *unversioned.UpdateManifest
	if reportFile != "" {
		updates, err = report.TryParseScanReport(reportFile, scanner, pkgTypes, libraryPatchLevel)
		if err != nil {
			return nil, err
		}

		// Filter updates based on package types
		pkgTypesList, err := parsePkgTypes(pkgTypes)
		if err != nil {
			return nil, fmt.Errorf("invalid package types: %w", err)
		}

		if updates != nil {
			// Filter OS updates
			if !shouldIncludeOSUpdates(pkgTypesList) {
				log.Debugf("Filtering out OS updates based on pkg-types: %v", pkgTypesList)
				updates.OSUpdates = []unversioned.UpdatePackage{}
			}

			// Filter library updates
			if !shouldIncludeLibraryUpdates(pkgTypesList) {
				log.Debugf("Filtering out library updates based on pkg-types: %v", pkgTypesList)
				updates.LangUpdates = []unversioned.UpdatePackage{}
			}

			log.Debugf("Filtered updates to apply: OS=%d, Lang=%d", len(updates.OSUpdates), len(updates.LangUpdates))

			// If after filtering there are zero OS and zero library updates, return an error
			// only when user explicitly requested some package types (default is OS) but none are patchable.
			if len(updates.OSUpdates) == 0 && len(updates.LangUpdates) == 0 {
				return nil, fmt.Errorf("no patchable vulnerabilities found in provided report for selected pkg-types (%s)", pkgTypes)
			}
		}

		log.Debugf("updates to apply: %v", updates)
	}

	// Create buildkit client
	bkClient, err := bkNewClient(ctx, bkOpts)
	if err != nil {
		return nil, err
	}
	defer bkClient.Close()

	// Resolve image reference
	ref := resolveImageReference(imageName)

	// Determine the loader type
	finalLoaderType := determineLoaderType(loader, bkOpts.Addr)

	// Check media type for OCI vs Docker export
	shouldExportOCI := shouldExportAsOCI(ref, finalLoaderType)

	// Create pipes for Docker export
	pipeR, pipeW := io.Pipe()

	// Create build configuration
	buildConfig, err := createBuildConfig(patchedImageName, shouldExportOCI, push, pipeW)
	if err != nil {
		return nil, err
	}

	// Create channels for build coordination
	buildChannel := make(chan *client.SolveStatus)
	eg, ctx := errgroup.WithContext(ctx)

	// Resolve image reference for BuildKit operations
	// For multi-platform images with local manifests, use platform-specific reference
	buildkitImageRef := imageName
	if multiPlatform {
		platformImageRef, err := buildkit.GetPlatformImageReference(image, &targetPlatform.Platform)
		if err == nil {
			// Successfully resolved platform-specific reference for local manifest
			log.Debugf("Using platform-specific image reference for BuildKit: %s", platformImageRef)
			buildkitImageRefNamed, err := reference.ParseNormalizedNamed(platformImageRef)
			if err == nil {
				buildkitImageRef = buildkitImageRefNamed
			}
		} else {
			log.Debugf("Could not resolve platform-specific reference, using original: %v", err)
		}
	}

	// Start the main build process and capture preserved states
	var patchResult *Result
	eg.Go(func() error {
		result, err := executePatchBuild(ctx, ch, bkClient, buildConfig, buildkitImageRef, &targetPlatform,
			workingFolder, updates, ignoreError, reportFile, format, output, patchedImageName, buildChannel, opts.ExitOnEOL)
		if err != nil {
			return err
		}
		patchResult = result
		return nil
	})

	// Display progress
	common.DisplayProgress(ctx, eg, buildChannel, opts.Progress)

	// Handle image loading if not pushing
	if !push {
		eg.Go(func() error {
			return loadImageToRuntime(ctx, pipeR, patchedImageName, finalLoaderType)
		})
	} else {
		go func() {
			pipeR.Close()
		}()
	}

	// Wait for completion
	if err := eg.Wait(); err != nil {
		return nil, err
	}

	// Get patched descriptor and add annotations, including preserved states
	return createPatchResultWithStates(imageName, patchedImageName, &targetPlatform, image, finalLoaderType, patchResult)
}

// validatePlatformEmulation checks if emulation is available for cross-platform builds.
func validatePlatformEmulation(targetPlatform types.PatchPlatform) error { //nolint:gocritic
	hostPlatform := platforms.Normalize(platforms.DefaultSpec())
	if hostPlatform.OS != LINUX {
		hostPlatform.OS = LINUX
	}

	platformsEqual := hostPlatform.OS == targetPlatform.OS &&
		hostPlatform.Architecture == targetPlatform.Architecture

	if platformsEqual {
		log.Debugf("Host platform %+v matches target platform %+v", hostPlatform, targetPlatform)
		return nil
	}

	log.Debugf("Host platform %+v does not match target platform %+v", hostPlatform, targetPlatform)

	if emulationEnabled := buildkit.QemuAvailable(&targetPlatform); !emulationEnabled {
		platform := targetPlatform.OS + "/" + targetPlatform.Architecture

		log.Warnf("Emulation is not enabled for platform %s.\n"+
			"To enable emulation, see docs: \n"+
			"https://docs.docker.com/build/building-multi-platform/#qemu",
			platform)

		return fmt.Errorf("emulation is not enabled for platform %s", platform)
	}

	log.Debugf("Emulation is enabled for platform %+v", targetPlatform)
	return nil
}

// setupWorkingFolder creates and configures the working directory.
func setupWorkingFolder(workingFolder string) (string, func(), error) {
	if workingFolder == "" {
		var err error
		workingFolder, err = os.MkdirTemp("", "copa-*")
		if err != nil {
			return "", nil, err
		}
		cleanup := func() { removeIfNotDebug(workingFolder) }
		if err = os.Chmod(workingFolder, 0o744); err != nil {
			cleanup()
			return "", nil, err
		}
		return workingFolder, cleanup, nil
	}

	isNew, err := utils.EnsurePath(workingFolder, 0o744)
	if err != nil {
		log.Errorf("failed to create workingFolder %s", workingFolder)
		return "", nil, err
	}

	cleanup := func() {}
	if isNew {
		cleanup = func() { removeIfNotDebug(workingFolder) }
	}

	return workingFolder, cleanup, nil
}

// resolveImageReference resolves the final image reference string.
func resolveImageReference(imageName reference.Named) string {
	if reference.IsNameOnly(imageName) {
		log.Warnf("Image name has no tag or digest, using latest as tag")
		return fmt.Sprintf("%s:%s", imageName.Name(), defaultTag)
	}
	log.Debugf("Image name has tag or digest, using %s as tag", imageName.String())
	return imageName.String()
}

// determineLoaderType determines the appropriate image loader.
func determineLoaderType(loader, bkAddr string) string {
	finalLoaderType := loader
	if finalLoaderType == "" {
		finalLoaderType = detectLoaderFromBuildkitAddr(bkAddr)
		if finalLoaderType != "" {
			log.Debugf("Auto-detected loader type %q from buildkit address %q", finalLoaderType, bkAddr)
		}
	}
	return finalLoaderType
}

// shouldExportAsOCI determines if the image should be exported as OCI format.
func shouldExportAsOCI(ref, loaderType string) bool {
	mt, err := utils.GetMediaType(ref, loaderType)
	shouldExportOCI := err == nil && strings.Contains(mt, "vnd.oci.image")

	switch {
	case shouldExportOCI:
		log.Debug("resolved media type is OCI")
	case err != nil:
		log.Warnf("unable to determine media type, defaulting to docker, err: %v", err)
	default:
		log.Warnf("resolved media type is Docker")
	}

	return shouldExportOCI
}

// loadImageToRuntime loads the built image into the container runtime.
func loadImageToRuntime(ctx context.Context, pipeR io.ReadCloser, patchedImageName, loaderType string) error {
	imgLoader, err := imageloader.New(ctx, imageloader.Config{Loader: loaderType})
	if err != nil {
		err = fmt.Errorf("failed to create loader: %w", err)
		if pipeReader, ok := pipeR.(*io.PipeReader); ok {
			pipeReader.CloseWithError(err)
		} else {
			pipeR.Close()
		}
		log.Error(err)
		return err
	}

	if err := imgLoader.Load(ctx, pipeR, patchedImageName); err != nil {
		err = fmt.Errorf("failed to load image: %w", err)
		if pipeReader, ok := pipeR.(*io.PipeReader); ok {
			pipeReader.CloseWithError(err)
		} else {
			pipeR.Close()
		}
		log.Error(err)
		return err
	}
	return pipeR.Close()
}

// createPatchResultWithStates creates the final patch result with descriptor, annotations, and preserved BuildKit states.
func createPatchResultWithStates(imageName reference.Named, patchedImageName string,
	targetPlatform *types.PatchPlatform, image, loaderType string, patchResult *Result,
) (*types.PatchResult, error) {
	// Use the appropriate runtime for image descriptor lookup
	runtime := imageloader.Docker
	if loaderType == imageloader.Podman {
		runtime = imageloader.Podman
	}

	// Use a fresh context for descriptor lookup to avoid cancellation issues
	// The original context might be canceled after the patching operation completes
	descriptorCtx := context.Background()
	patchedDesc, err := utils.GetImageDescriptor(descriptorCtx, patchedImageName, runtime)
	if err != nil {
		prettyPlatform := platforms.Format(targetPlatform.Platform)
		log.Warnf("failed to get patched image descriptor for platform '%s': %v", prettyPlatform, err)
	}

	// Add original manifest annotations if we have a patched descriptor
	if patchedDesc != nil {
		originalAnnotations, err := utils.GetPlatformManifestAnnotations(descriptorCtx, image, &ispec.Platform{
			OS:           targetPlatform.OS,
			Architecture: targetPlatform.Architecture,
			Variant:      targetPlatform.Variant,
		})
		if err != nil {
			log.Warnf("Failed to get original manifest level annotations for platform %s: %v", targetPlatform.Platform, err)
		} else if len(originalAnnotations) > 0 {
			// Create augmented descriptor with original annotations
			augmentedDesc := *patchedDesc
			if augmentedDesc.Annotations == nil {
				augmentedDesc.Annotations = make(map[string]string)
			}

			// Copy original annotations
			maps.Copy(augmentedDesc.Annotations, originalAnnotations)

			// Update creation timestamp and add Copa annotations
			augmentedDesc.Annotations["org.opencontainers.image.created"] = time.Now().UTC().Format(time.RFC3339)
			augmentedDesc.Annotations[copaAnnotationKeyPrefix+".image.patched"] = time.Now().UTC().Format(time.RFC3339)

			patchedDesc = &augmentedDesc
			log.Debugf("Preserved %d manifest level annotations for platform %s", len(originalAnnotations), targetPlatform.Platform)
		}
	}

	patchedRef, err := reference.ParseNamed(patchedImageName)
	log.Debugf("Patched image name: %s", patchedImageName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse patched image name %s: %w", patchedImageName, err)
	}

	result := &types.PatchResult{
		OriginalRef: imageName,
		PatchedRef:  patchedRef,
		PatchedDesc: patchedDesc,
	}

	// Include preserved BuildKit states if available
	if patchResult != nil {
		result.PatchedState = patchResult.PatchedState
		result.ConfigData = patchResult.ConfigData
	}

	return result, nil
}

// executePatchBuild executes the actual patch build process.
func executePatchBuild(
	ctx context.Context,
	ch chan error,
	bkClient *client.Client,
	buildConfig *BuildConfig,
	imageName reference.Named,
	targetPlatform *types.PatchPlatform,
	workingFolder string,
	updates *unversioned.UpdateManifest,
	ignoreError bool,
	reportFile, format, output, patchedImageName string,
	buildChannel chan *client.SolveStatus,
	exitOnEOL bool,
) (*Result, error) {
	var pkgType string
	var validatedManifest *unversioned.UpdateManifest
	var patchResult *Result // Store the patch result with preserved states

	if updates != nil {
		// create a new manifest with the successfully patched packages
		validatedManifest = &unversioned.UpdateManifest{
			Metadata: unversioned.Metadata{
				OS: unversioned.OS{
					Type:    updates.Metadata.OS.Type,
					Version: updates.Metadata.OS.Version,
				},
				Config: unversioned.Config{
					Arch: updates.Metadata.Config.Arch,
				},
			},
			OSUpdates:   []unversioned.UpdatePackage{},
			LangUpdates: []unversioned.UpdatePackage{},
		}
	}

	solveResponse, err := bkClient.Build(ctx, buildConfig.SolveOpt, copaProduct, func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
		// Create patch context and options
		patchCtx := &Context{
			Context: ctx,
			Client:  c,
		}

		patchOpts := &Options{
			ImageName:        imageName.String(),
			TargetPlatform:   targetPlatform,
			Updates:          updates,
			ValidatedUpdates: validatedManifest,
			WorkingFolder:    workingFolder,
			IgnoreError:      ignoreError,
			ErrorChannel:     ch,
			ReturnState:      false, // Always solve for Docker export
			ExitOnEOL:        exitOnEOL,
		}

		// Execute the core patching logic
		result, err := ExecutePatchCore(patchCtx, patchOpts)
		if err != nil {
			return nil, err
		}

		// Store the result with preserved states for later use
		patchResult = result

		// Update validation data for VEX document generation
		pkgType = result.PackageType

		// Build validated manifest (exclude errored packages) using original updates + result.ErroredPackages
		if validatedManifest != nil && updates != nil {
			errored := map[string]struct{}{}
			for _, e := range result.ErroredPackages {
				errored[e] = struct{}{}
			}
			for _, u := range updates.OSUpdates {
				if _, bad := errored[u.Name]; !bad {
					validatedManifest.OSUpdates = append(validatedManifest.OSUpdates, u)
				}
			}
			for _, u := range updates.LangUpdates {
				if _, bad := errored[u.Name]; !bad {
					validatedManifest.LangUpdates = append(validatedManifest.LangUpdates, u)
				}
			}
		}

		return result.Result, nil
	}, buildChannel)

	// Currently can only validate updates if updating via scanner
	var patchedImageDigest string
	if err == nil && solveResponse != nil {
		digest := solveResponse.ExporterResponse[exptypes.ExporterImageDigestKey]
		patchedImageDigest = digest
	}
	if patchedImageDigest != "" && reportFile != "" && validatedManifest != nil {
		nameDigestOrTag := common.GetRepoNameWithDigest(patchedImageName, patchedImageDigest)
		// vex document must contain at least one statement
		if output != "" && (len(validatedManifest.OSUpdates) > 0 || len(validatedManifest.LangUpdates) > 0) {
			if err := vex.TryOutputVexDocument(validatedManifest, pkgType, nameDigestOrTag, format, output); err != nil {
				ch <- err
				return nil, err
			}
		}
	}

	return patchResult, err
}

// shouldIncludeOSUpdates returns true if OS updates should be included based on package types.
func shouldIncludeOSUpdates(pkgTypes []string) bool {
	return slices.Contains(pkgTypes, utils.PkgTypeOS)
}

// shouldIncludeLibraryUpdates returns true if library updates should be included based on package types.
func shouldIncludeLibraryUpdates(pkgTypes []string) bool {
	return slices.Contains(pkgTypes, utils.PkgTypeLibrary)
}

// validateLibraryPkgTypesRequireReport validates that library package types require a scanner report.
func validateLibraryPkgTypesRequireReport(pkgTypes []string, reportProvided bool) error {
	if shouldIncludeLibraryUpdates(pkgTypes) && !reportProvided {
		return fmt.Errorf("library package types require a scanner report file to be provided")
	}
	return nil
}

// Package types supported by copa
// parsePkgTypes parses a comma-separated string of package types and validates them.
func parsePkgTypes(pkgTypesStr string) ([]string, error) {
	if pkgTypesStr == "" {
		return []string{utils.PkgTypeOS}, nil // default to OS
	}

	types := strings.Split(pkgTypesStr, ",")
	validTypes := []string{}

	for _, t := range types {
		t = strings.TrimSpace(t)
		if t == utils.PkgTypeOS || t == utils.PkgTypeLibrary {
			validTypes = append(validTypes, t)
		} else {
			return nil, fmt.Errorf("invalid package type '%s'. Valid types are: %s, %s", t, utils.PkgTypeOS, utils.PkgTypeLibrary)
		}
	}

	if len(validTypes) == 0 {
		return []string{utils.PkgTypeOS}, nil // default to OS
	}

	return validTypes, nil
}
