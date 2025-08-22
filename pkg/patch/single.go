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

// getRepoNameWithDigest extracts repo name with digest from image name and digest.
// e.g. "docker.io/library/nginx:1.21.6-patched" -> "nginx@sha256:...".
func getRepoNameWithDigest(patchedImageName, imageDigest string) string {
	parts := strings.Split(patchedImageName, "/")
	last := parts[len(parts)-1]
	if idx := strings.IndexRune(last, ':'); idx >= 0 {
		last = last[:idx]
	}
	nameWithDigest := fmt.Sprintf("%s@%s", last, imageDigest)
	return nameWithDigest
}

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
	patchedTag, err = common.ResolvePatchedTag(imageName, patchedTag, suffix)
	if err != nil {
		return nil, err
	}
	if multiPlatform {
		patchedTag = archTag(patchedTag, targetPlatform.Architecture, targetPlatform.Variant)
	}
	patchedImageName := fmt.Sprintf("%s:%s", imageName.Name(), patchedTag)
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
		updates, err = report.TryParseScanReport(reportFile, scanner)
		if err != nil {
			return nil, err
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
	buildConfig, err := createBuildConfig(patchedImageName, shouldExportOCI, push, bkOpts, pipeW)
	if err != nil {
		return nil, err
	}

	// Create channels for build coordination
	buildChannel := make(chan *client.SolveStatus)
	eg, ctx := errgroup.WithContext(ctx)

	// Start the main build process
	eg.Go(func() error {
		return executePatchBuild(ctx, ch, bkClient, buildConfig, imageName, &targetPlatform,
			workingFolder, updates, ignoreError, reportFile, scanner, format, output, patchedImageName, buildChannel)
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

	// Get patched descriptor and add annotations
	return createPatchResult(ctx, imageName, patchedImageName, &targetPlatform, image, finalLoaderType)
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
		return fmt.Errorf("emulation is not enabled for platform %s", targetPlatform.OS+"/"+targetPlatform.Architecture)
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

// createPatchResult creates the final patch result with descriptor and annotations.
func createPatchResult(ctx context.Context, imageName reference.Named, patchedImageName string,
	targetPlatform *types.PatchPlatform, image, loaderType string,
) (*types.PatchResult, error) {
	// Use the appropriate runtime for image descriptor lookup
	runtime := imageloader.Docker
	if loaderType == imageloader.Podman {
		runtime = imageloader.Podman
	}

	patchedDesc, err := utils.GetImageDescriptor(ctx, patchedImageName, runtime)
	if err != nil {
		prettyPlatform := platforms.Format(targetPlatform.Platform)
		log.Warnf("failed to get patched image descriptor for platform '%s': %v", prettyPlatform, err)
	}

	// Add original manifest annotations if we have a patched descriptor
	if patchedDesc != nil {
		originalAnnotations, err := utils.GetPlatformManifestAnnotations(ctx, image, &ispec.Platform{
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

	return &types.PatchResult{
		OriginalRef: imageName,
		PatchedRef:  patchedRef,
		PatchedDesc: patchedDesc,
	}, nil
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
	reportFile, _, format, output, patchedImageName string,
	buildChannel chan *client.SolveStatus,
) error {
	var pkgType string
	var validatedManifest *unversioned.UpdateManifest
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
			Updates: []unversioned.UpdatePackage{},
		}
	}

	solveResponse, err := bkClient.Build(ctx, buildConfig.SolveOpt, copaProduct, func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
		// Create patch context and options
		patchCtx := &Context{
			Context: ctx,
			Client:  c,
		}

		patchOpts := &Options{
			ImageName:      imageName.String(),
			TargetPlatform: targetPlatform,
			Updates:        updates,
			WorkingFolder:  workingFolder,
			IgnoreError:    ignoreError,
			ErrorChannel:   ch,
		}

		// Execute the core patching logic
		result, err := ExecutePatchCore(patchCtx, patchOpts)
		if err != nil {
			return nil, err
		}

		// Update validation data for VEX document generation
		pkgType = result.PackageType
		if validatedManifest != nil {
			validatedManifest.Updates = result.ValidatedUpdates
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
		nameDigestOrTag := getRepoNameWithDigest(patchedImageName, patchedImageDigest)
		// vex document must contain at least one statement
		if output != "" && len(validatedManifest.Updates) > 0 {
			if err := vex.TryOutputVexDocument(validatedManifest, pkgType, nameDigestOrTag, format, output); err != nil {
				ch <- err
				return err
			}
		}
	}

	return err
}
