package patch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/containerd/platforms"
	"github.com/docker/buildx/build"
	"github.com/docker/cli/cli/config"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"

	"github.com/distribution/reference"
	"github.com/docker/buildx/util/imagetools"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	"github.com/moby/buildkit/util/progress/progressui"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/imageloader"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/project-copacetic/copacetic/pkg/vex"
	"github.com/quay/claircore/osrelease"
)

const (
	copaProduct             = "copa"
	defaultRegistry         = "docker.io"
	defaultTag              = "latest"
	LINUX                   = "linux"
	ARM64                   = "arm64"
	copaAnnotationKeyPrefix = "sh.copa"
)

// for testing.
var (
	bkNewClient = buildkit.NewClient
)

// detectLoaderFromBuildkitAddr attempts to determine the appropriate loader.
// based on the buildkit connection address scheme.
func detectLoaderFromBuildkitAddr(addr string) string {
	if addr == "" {
		return ""
	}

	u, err := url.Parse(addr)
	if err != nil {
		log.Debugf("Failed to parse buildkit address %q: %v", addr, err)
		return ""
	}

	switch u.Scheme {
	case "podman-container":
		return imageloader.Podman
	case "docker-container", "docker", "buildx":
		return imageloader.Docker
	default:
		// Unknown scheme, let imageloader auto-detect
		return ""
	}
}

// archTag returns "patched-arm64" or "patched-arm-v7" etc.
func archTag(base, arch, variant string) string {
	if variant != "" {
		return fmt.Sprintf("%s-%s-%s", base, arch, variant)
	}
	return fmt.Sprintf("%s-%s", base, arch)
}

// createMultiPlatformManifest assembles a multi-platform manifest list and pushes it
// via Buildx's imagetools helper (equivalent to
// `docker buildx imagetools create --tag … img@sha256:d1 img@sha256:d2 …`).
func createMultiPlatformManifest(
	ctx context.Context,
	imageName reference.NamedTagged,
	items []types.PatchResult,
	originalImage string,
) error {
	resolver := imagetools.New(imagetools.Opt{
		Auth: config.LoadDefaultConfigFile(os.Stderr),
	})

	// fetch annotations from the original image
	annotations := make(map[exptypes.AnnotationKey]string)

	// get the original image index manifest annotations
	originalAnnotations, err := utils.GetIndexManifestAnnotations(ctx, originalImage)
	if err != nil {
		log.Warnf("Failed to get original image annotations: %v", err)
		// continue without annotations rather than failing
	} else {
		log.Infof("Retrieved %d annotations from original image %s", len(originalAnnotations), originalImage)
		if len(originalAnnotations) > 0 {
			// copy all annotations from the original image
			for k, v := range originalAnnotations {
				// create an AnnotationKey for index level annotations
				ak := exptypes.AnnotationKey{
					Type: exptypes.AnnotationIndex,
					Key:  k,
				}
				annotations[ak] = v
			}

			// update annotations that should reflect the patched state
			// update the created timestamp to reflect when the patch was applied
			createdKey := exptypes.AnnotationKey{
				Type: exptypes.AnnotationIndex,
				Key:  "org.opencontainers.image.created",
			}
			annotations[createdKey] = time.Now().UTC().Format(time.RFC3339)

			// if theres a version annotation, update it to reflect the patched tag
			versionKey := exptypes.AnnotationKey{
				Type: exptypes.AnnotationIndex,
				Key:  "org.opencontainers.image.version",
			}
			if version, ok := annotations[versionKey]; ok {
				// Extract the tag from the patched image name to determine what suffix to use
				patchedTag := imageName.Tag()

				// Try to determine what was added to the original version
				// If the patched tag contains the original version, extract the suffix
				if strings.Contains(patchedTag, version) {
					// Use the full patched tag as the new version
					annotations[versionKey] = patchedTag
				} else {
					// Fallback: append the patched tag as a suffix
					annotations[versionKey] = version + "-" + patchedTag
				}
			}

			log.Debugf("Preserving %d annotations from original image", len(annotations))
		} else {
			log.Info("No annotations found in original image, adding Copa annotations only")
			// add Copa-specific annotations even if there are no original annotations
			createdKey := exptypes.AnnotationKey{
				Type: exptypes.AnnotationIndex,
				Key:  "org.opencontainers.image.created",
			}
			annotations[createdKey] = time.Now().UTC().Format(time.RFC3339)
		}
	}

	// add manifest descriptor level annotations for each platform
	for _, it := range items {
		if it.PatchedDesc != nil && it.PatchedDesc.Platform != nil {
			// use annotations that are already preserved in PatchedDesc.Annotations
			// this works for both patched and pass-through platforms
			if len(it.PatchedDesc.Annotations) > 0 {
				// add each annotation as a manifest-descriptor annotation
				for k, v := range it.PatchedDesc.Annotations {
					ak := exptypes.AnnotationKey{
						Type:     exptypes.AnnotationManifestDescriptor,
						Platform: it.PatchedDesc.Platform,
						Key:      k,
					}
					// for patched platforms, update creation timestamp to reflect patching
					// for other platforms, preserve original timestamps
					if k == "org.opencontainers.image.created" && it.PatchedRef != it.OriginalRef {
						// this is a patched platform, update the timestamp
						annotations[ak] = time.Now().UTC().Format(time.RFC3339)
					} else {
						// this is a platform with preserved or non-timestamp annotation
						annotations[ak] = v
					}
				}
				log.Debugf("Added %d manifest-descriptor annotations for platform %s", len(it.PatchedDesc.Annotations), platforms.Format(*it.PatchedDesc.Platform))
			}
		}
	}

	// Source references (repo@sha256:digest) – one per architecture.
	srcRefs := make([]*imagetools.Source, 0, len(items))
	for _, it := range items {
		if it.PatchedDesc == nil {
			return fmt.Errorf("patched descriptor is nil for %s", it.OriginalRef.String())
		}

		srcRefs = append(srcRefs, &imagetools.Source{
			Ref:  it.PatchedRef,
			Desc: *it.PatchedDesc,
		})
	}

	idxBytes, desc, err := resolver.Combine(ctx, srcRefs, annotations, false)
	if err != nil {
		return fmt.Errorf("failed to combine sources into manifest list: %w", err)
	}

	err = resolver.Push(ctx, imageName, desc, idxBytes)
	if err != nil {
		return fmt.Errorf("failed to push multi-platform manifest list: %w", err)
	}

	return nil
}

func normalizeConfigForPlatform(j []byte, p *types.PatchPlatform) ([]byte, error) {
	if p == nil {
		return j, fmt.Errorf("platform is nil")
	}

	var m map[string]any
	if err := json.Unmarshal(j, &m); err != nil {
		return nil, err
	}

	m["architecture"] = p.Architecture
	if p.Variant != "" {
		m["variant"] = p.Variant
	} else {
		delete(m, "variant")
	}
	m["os"] = p.OS

	return json.Marshal(m)
}

// Patch command applies package updates to an OCI image given a vulnerability report.
func Patch(
	ctx context.Context, timeout time.Duration,
	image, reportPath, patchedTag, suffix, workingFolder, scanner, format, output, loader string,
	ignoreError, push bool,
	targetPlatforms []string,
	bkOpts buildkit.Opts,
) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan error)
	go func() {
		ch <- patchWithContext(timeoutCtx, ch, image, reportPath, patchedTag, suffix, workingFolder, scanner, format, output, loader, ignoreError, push, targetPlatforms, bkOpts)
	}()

	select {
	case err := <-ch:
		return err
	case <-timeoutCtx.Done():
		// add a grace period for long running deferred cleanup functions to complete
		<-time.After(1 * time.Second)

		err := fmt.Errorf("patch exceeded timeout %v", timeout)
		log.Error(err)
		return err
	}
}

func removeIfNotDebug(workingFolder string) {
	if log.GetLevel() >= log.DebugLevel {
		// Keep the intermediate outputs for outputs solved to working folder if debugging
		log.Warnf("--debug specified, working folder at %s needs to be manually cleaned up", workingFolder)
	} else {
		os.RemoveAll(workingFolder)
	}
}

func patchWithContext(
	ctx context.Context,
	ch chan error,
	image, reportPath, patchedTag, suffix, workingFolder, scanner, format, output, loader string,
	ignoreError, push bool,
	targetPlatforms []string,
	bkOpts buildkit.Opts,
) error {
	// Handle empty report path - check if image is manifest list or single arch
	if reportPath == "" {
		// Discover platforms from the image reference to determine if it's multi-arch
		discoveredPlatforms, err := buildkit.DiscoverPlatformsFromReference(image)
		if err != nil {
			// Failed to discover platforms - treat as single-arch image
			log.Warnf("Failed to discover platforms for image %s (treating as single-arch): %v", image, err)
			if len(targetPlatforms) > 0 {
				log.Info("Platform flag ignored when platform discovery fails")
			}

			// Fallback to default platform
			platform := types.PatchPlatform{
				Platform:       platforms.Normalize(platforms.DefaultSpec()),
				ReportFile:     "",
				ShouldPreserve: false,
			}
			if platform.OS != LINUX {
				platform.OS = LINUX
			}

			result, err := patchSingleArchImage(ctx, ch, image, "", patchedTag, suffix, workingFolder, scanner, format, output, loader, platform, ignoreError, push, bkOpts, false)
			if err == nil && result != nil && result.PatchedRef != nil {
				log.Infof("Patched image (%s): %s\n", platform.OS+"/"+platform.Architecture, result.PatchedRef)
			}
			return err
		}

		if len(discoveredPlatforms) <= 1 {
			// Single-arch image - ignore platform flag
			log.Debugf("Detected single-arch image")
			if len(targetPlatforms) > 0 {
				log.Info("Platform flag ignored for single-arch image")
			}

			platform := types.PatchPlatform{
				Platform:       platforms.Normalize(platforms.DefaultSpec()),
				ReportFile:     "",
				ShouldPreserve: false,
			}
			if platform.OS != LINUX {
				platform.OS = LINUX
			}

			result, err := patchSingleArchImage(ctx, ch, image, "", patchedTag, suffix, workingFolder, scanner, format, output, loader, platform, ignoreError, push, bkOpts, false)
			if err == nil && result != nil && result.PatchedRef != nil {
				log.Infof("Patched image (%s): %s\n", platform.OS+"/"+platform.Architecture, result.PatchedRef)
			}
			return err
		}

		log.Debugf("Detected multi-platform image with %d platforms", len(discoveredPlatforms))
		return patchMultiPlatformImage(ctx, ch, image, "", patchedTag, suffix, workingFolder, scanner, format, output, loader, ignoreError, push, bkOpts, targetPlatforms, discoveredPlatforms)
	}

	// Check if reportPath exists
	if _, err := os.Stat(reportPath); os.IsNotExist(err) {
		return fmt.Errorf("report path %s does not exist", reportPath)
	}

	// Get file info to determine if it's a file or directory
	f, err := os.Stat(reportPath)
	if err != nil {
		return fmt.Errorf("failed to stat report path %s: %w", reportPath, err)
	}

	if f.IsDir() {
		// Handle directory - multi-platform patching
		log.Debugf("Using report directory: %s", reportPath)
		if len(targetPlatforms) > 0 {
			log.Info("Platform flag ignored when report directory is provided")
		}
		return patchMultiPlatformImage(ctx, ch, image, reportPath, patchedTag, suffix, workingFolder, scanner, format, output, loader, ignoreError, push, bkOpts, nil, nil)
	}
	// Handle file - single-arch patching
	log.Debugf("Using report file: %s", reportPath)
	platform := types.PatchPlatform{
		Platform: platforms.Normalize(platforms.DefaultSpec()),
	}
	if platform.OS != LINUX {
		platform.OS = LINUX
	}
	result, err := patchSingleArchImage(ctx, ch, image, reportPath, patchedTag, suffix, workingFolder, scanner, format, output, loader, platform, ignoreError, push, bkOpts, false)
	if err == nil && result != nil {
		log.Infof("Patched image (%s): %s\n", platform.OS+"/"+platform.Architecture, result.PatchedRef.String())
	}
	return err
}

func patchSingleArchImage(
	ctx context.Context,
	ch chan error,
	image, reportFile, patchedTag, suffix, workingFolder, scanner, format, output, loader string,
	//nolint:gocritic
	targetPlatform types.PatchPlatform,
	ignoreError, push bool,
	bkOpts buildkit.Opts,
	multiPlatform bool,
) (*types.PatchResult, error) {
	if reportFile == "" && output != "" {
		log.Warn("No vulnerability report was provided, so no VEX output will be generated.")
	}

	// if the target platform is different from the host platform, we need to check if emulation is enabled
	// only need to do this check if were patching a multi-platform image
	if multiPlatform {
		hostPlatform := platforms.Normalize(platforms.DefaultSpec())
		if hostPlatform.OS != LINUX {
			hostPlatform.OS = LINUX
		}
		platformsEqual := hostPlatform.OS == targetPlatform.OS &&
			hostPlatform.Architecture == targetPlatform.Architecture
		if platformsEqual {
			log.Debugf("Host platform %+v matches target platform %+v", hostPlatform, targetPlatform)
		} else {
			log.Debugf("Host platform %+v does not match target platform %+v", hostPlatform, targetPlatform)
			// check if emulation is enabled

			if emulationEnabled := buildkit.QemuAvailable(&targetPlatform); !emulationEnabled {
				return nil, fmt.Errorf("emulation is not enabled for platform %s", targetPlatform.OS+"/"+targetPlatform.Architecture)
			}
			log.Debugf("Emulation is enabled for platform %+v", targetPlatform)
		}
	}

	// parse the image reference
	imageName, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference: %w", err)
	}

	// resolve final patched tag
	patchedTag, err = resolvePatchedTag(imageName, patchedTag, suffix)
	if err != nil {
		return nil, err
	}
	if multiPlatform {
		patchedTag = archTag(patchedTag, targetPlatform.Architecture, targetPlatform.Variant)
	}
	patchedImageName := fmt.Sprintf("%s:%s", imageName.Name(), patchedTag)
	log.Infof("Patched image name: %s", patchedImageName)

	// Ensure working folder exists for call to InstallUpdates
	if workingFolder == "" {
		var err error
		workingFolder, err = os.MkdirTemp("", "copa-*")
		if err != nil {
			return nil, err
		}
		defer removeIfNotDebug(workingFolder)
		if err = os.Chmod(workingFolder, 0o744); err != nil {
			return nil, err
		}
	} else {
		if isNew, err := utils.EnsurePath(workingFolder, 0o744); err != nil {
			log.Errorf("failed to create workingFolder %s", workingFolder)
			return nil, err
		} else if isNew {
			defer removeIfNotDebug(workingFolder)
		}
	}

	var updates *unversioned.UpdateManifest
	// Parse report for update packages
	if reportFile != "" {
		updates, err = report.TryParseScanReport(reportFile, scanner)
		if err != nil {
			return nil, err
		}
		log.Debugf("updates to apply: %v", updates)
	}

	bkClient, err := bkNewClient(ctx, bkOpts)
	if err != nil {
		return nil, err
	}
	defer bkClient.Close()

	var ref string
	if reference.IsNameOnly(imageName) {
		log.Warnf("Image name has no tag or digest, using latest as tag")
		ref = fmt.Sprintf("%s:%s", imageName.Name(), defaultTag)
	} else {
		log.Debugf("Image name has tag or digest, using %s as tag", imageName.String())
		ref = imageName.String()
	}

	// Determine the loader type before starting goroutines
	finalLoaderType := loader
	if finalLoaderType == "" {
		finalLoaderType = detectLoaderFromBuildkitAddr(bkOpts.Addr)
		if finalLoaderType != "" {
			log.Debugf("Auto-detected loader type %q from buildkit address %q", finalLoaderType, bkOpts.Addr)
		}
	}

	// get the original media type of the image to determine if we should export as OCI or Docker
	mt, err := utils.GetMediaType(ref, finalLoaderType)
	shouldExportOCI := err == nil && strings.Contains(mt, "vnd.oci.image")

	switch {
	case shouldExportOCI:
		log.Debug("resolved media type is OCI")

	case err != nil:
		log.Warnf("unable to determine media type, defaulting to docker, err: %v", err)

	default:
		log.Warnf("resolved media type is Docker")
	}

	pipeR, pipeW := io.Pipe()
	dockerConfig := config.LoadDefaultConfigFile(os.Stderr)
	cfg := authprovider.DockerAuthProviderConfig{ConfigFile: dockerConfig}
	attachable := []session.Attachable{authprovider.NewDockerAuthProvider(cfg)}

	// create solve options based on whether were pushing to registry or loading to docker
	solveOpt := client.SolveOpt{
		Frontend: "",         // i.e. we are passing in the llb.Definition directly
		Session:  attachable, // used for authprovider, sshagentprovider and secretprovider
	}

	// determine which attributes to set for the export
	attrs := map[string]string{
		"name": patchedImageName,
		"annotation." + copaAnnotationKeyPrefix + ".image.patched": time.Now().UTC().Format(time.RFC3339),
	}
	if shouldExportOCI {
		attrs["oci-mediatypes"] = "true"
	}
	if push {
		attrs["push"] = "true"
		solveOpt.Exports = []client.ExportEntry{
			{
				Type:  client.ExporterImage,
				Attrs: attrs,
			},
		}
	} else {
		solveOpt.Exports = []client.ExportEntry{
			{
				Type:  client.ExporterDocker,
				Attrs: attrs,
				Output: func(_ map[string]string) (io.WriteCloser, error) {
					return pipeW, nil
				},
			},
		}
	}
	solveOpt.SourcePolicy, err = build.ReadSourcePolicy()
	if err != nil {
		return nil, err
	}

	if solveOpt.SourcePolicy != nil {
		switch {
		case strings.Contains(solveOpt.SourcePolicy.Rules[0].Updates.Identifier, "redhat"):
			err = errors.New("RedHat is not supported via source policies due to BusyBox not being in the RHEL repos\n" +
				"Please use a different RPM-based image")
			return nil, err

		case strings.Contains(solveOpt.SourcePolicy.Rules[0].Updates.Identifier, "rockylinux"):
			err = errors.New("RockyLinux is not supported via source policies due to BusyBox not being in the RockyLinux repos\n" +
				"Please use a different RPM-based image")
			return nil, err

		case strings.Contains(solveOpt.SourcePolicy.Rules[0].Updates.Identifier, "alma"):
			err = errors.New("AlmaLinux is not supported via source policies due to BusyBox not being in the AlmaLinux repos\n" +
				"Please use a different RPM-based image")
			return nil, err
		}
	}

	// Create a channel to receive the patched image digest
	buildChannel := make(chan *client.SolveStatus)
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
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

		solveResponse, err := bkClient.Build(ctx, solveOpt, copaProduct, func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
			// Configure buildctl/client for use by package manager
			config, err := buildkit.InitializeBuildkitConfig(ctx, c, imageName.String())
			if err != nil {
				ch <- err
				return nil, err
			}

			// Create package manager helper
			var manager pkgmgr.PackageManager
			if reportFile == "" {
				// determine OS family
				fileBytes, err := buildkit.ExtractFileFromState(ctx, c, &config.ImageState, "/etc/os-release")
				if err != nil {
					ch <- err
					return nil, fmt.Errorf("unable to extract /etc/os-release file from state %w", err)
				}

				osType, err := getOSType(ctx, fileBytes)
				if err != nil {
					ch <- err
					return nil, err
				}

				osVersion, err := getOSVersion(ctx, fileBytes)
				if err != nil {
					ch <- err
					return nil, err
				}

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

				// get package manager based on os family type
				manager, err = pkgmgr.GetPackageManager(osType, osVersion, config, workingFolder)
				if err != nil {
					ch <- err
					return nil, err
				}
			} else {
				// get package manager based on os family type
				manager, err = pkgmgr.GetPackageManager(updates.Metadata.OS.Type, updates.Metadata.OS.Version, config, workingFolder)
				if err != nil {
					ch <- err
					return nil, err
				}
			}

			// Export the patched image state to Docker
			patchedImageState, errPkgs, err := manager.InstallUpdates(ctx, updates, ignoreError)
			if err != nil {
				ch <- err
				return nil, err
			}

			def, err := patchedImageState.Marshal(ctx, llb.Platform(targetPlatform.Platform))
			if err != nil {
				ch <- err
				return nil, fmt.Errorf("unable to get platform from ImageState %w", err)
			}

			res, err := c.Solve(ctx, gwclient.SolveRequest{
				Definition: def.ToPB(),
				Evaluate:   true,
			})
			if err != nil {
				ch <- err
				return nil, err
			}

			fixed, err := normalizeConfigForPlatform(config.ConfigData, &targetPlatform)
			if err != nil {
				ch <- err
				return nil, err
			}
			res.AddMeta(exptypes.ExporterImageConfigKey, fixed)

			// for the vex document, only include updates that were successfully applied
			pkgType = manager.GetPackageType()
			if validatedManifest != nil {
				for _, update := range updates.Updates {
					if !slices.Contains(errPkgs, update.Name) {
						validatedManifest.Updates = append(validatedManifest.Updates, update)
					}
				}
			}

			return res, nil
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
	})

	eg.Go(func() error {
		// not using shared context to not disrupt display but let us finish reporting errors
		mode := progressui.AutoMode
		if log.GetLevel() >= log.DebugLevel {
			mode = progressui.PlainMode
		}
		display, err := progressui.NewDisplay(os.Stderr, mode)
		if err != nil {
			return err
		}

		_, err = display.UpdateFrom(ctx, buildChannel)
		return err
	})

	// only load to docker if not pushing
	if !push {
		eg.Go(func() error {
			imgLoader, err := imageloader.New(ctx, imageloader.Config{Loader: finalLoaderType})
			if err != nil {
				err = fmt.Errorf("failed to create loader: %w", err)
				pipeR.CloseWithError(err)
				log.Error(err)
				return err
			}

			if err := imgLoader.Load(ctx, pipeR, patchedImageName); err != nil {
				err = fmt.Errorf("failed to load image: %w", err)
				pipeR.CloseWithError(err)
				log.Error(err)
				return err
			}
			return pipeR.Close()
		})
	} else {
		go func() {
			pipeR.Close()
		}()
	}

	err = eg.Wait()
	if err != nil {
		return nil, err
	}

	// Use the appropriate runtime for image descriptor lookup
	runtime := imageloader.Docker
	if finalLoaderType == imageloader.Podman {
		runtime = imageloader.Podman
	}

	patchedDesc, err := utils.GetImageDescriptor(context.Background(), patchedImageName, runtime)
	if err != nil { // dont necessarily need to fail if we can't get the descriptor
		prettyPlatform := platforms.Format(targetPlatform.Platform)
		log.Warnf("failed to get patched image descriptor for platform '%s':  %v", prettyPlatform, err)
	}

	// if we have a patched descriptor then augment it with original manifest level annotations
	if patchedDesc != nil {
		// get the original manifest level annotations for this platform
		originalAnnotations, err := utils.GetPlatformManifestAnnotations(ctx, image, &ispec.Platform{
			OS:           targetPlatform.OS,
			Architecture: targetPlatform.Architecture,
			Variant:      targetPlatform.Variant,
		})
		if err != nil {
			log.Warnf("Failed to get original manifest level annotations for platform %s: %v", targetPlatform.Platform, err)
		} else if len(originalAnnotations) > 0 {
			// create a new descriptor that includes the original manifest level annotations
			augmentedDesc := *patchedDesc
			if augmentedDesc.Annotations == nil {
				augmentedDesc.Annotations = make(map[string]string)
			}

			// copy original annotations
			maps.Copy(augmentedDesc.Annotations, originalAnnotations)

			// update creation timestamp to reflect patching
			augmentedDesc.Annotations["org.opencontainers.image.created"] = time.Now().UTC().Format(time.RFC3339)

			// add Copa image.patched annotation for patched platforms
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

// resolvePatchedTag merges explicit tag & suffix rules, returning the final patched tag.
func resolvePatchedTag(imageRef reference.Named, explicitTag, suffix string) (string, error) {
	// if user explicitly sets a final tag, that wins outright
	if explicitTag != "" {
		return explicitTag, nil
	}

	// parse out any existing tag from the image ref
	var baseTag string
	if tagged, ok := imageRef.(reference.Tagged); ok {
		baseTag = tagged.Tag()
	}

	// if suffix is empty, default to "patched"
	if suffix == "" {
		suffix = "patched"
	}

	// if we have no original baseTag (the user’s image had no tag),
	// then we can’t append a suffix to it
	if baseTag == "" {
		return "", fmt.Errorf("no tag found in image reference %s", imageRef.String())
	}

	// otherwise, combine them
	return fmt.Sprintf("%s-%s", baseTag, suffix), nil
}

func getOSType(ctx context.Context, osreleaseBytes []byte) (string, error) {
	r := bytes.NewReader(osreleaseBytes)
	osData, err := osrelease.Parse(ctx, r)
	if err != nil {
		return "", fmt.Errorf("unable to parse os-release data %w", err)
	}

	osType := strings.ToLower(osData["NAME"])
	switch {
	case strings.Contains(osType, "alpine"):
		return "alpine", nil
	case strings.Contains(osType, "debian"):
		return "debian", nil
	case strings.Contains(osType, "ubuntu"):
		return "ubuntu", nil
	case strings.Contains(osType, "amazon"):
		return "amazon", nil
	case strings.Contains(osType, "centos"):
		return "centos", nil
	case strings.Contains(osType, "mariner"):
		return "cbl-mariner", nil
	case strings.Contains(osType, "azure linux"):
		return "azurelinux", nil
	case strings.Contains(osType, "red hat"):
		return "redhat", nil
	case strings.Contains(osType, "rocky"):
		return "rocky", nil
	case strings.Contains(osType, "oracle"):
		return "oracle", nil
	case strings.Contains(osType, "alma"):
		return "alma", nil
	default:
		log.Error("unsupported osType ", osType)
		return "", errors.ErrUnsupported
	}
}

func getOSVersion(ctx context.Context, osreleaseBytes []byte) (string, error) {
	r := bytes.NewReader(osreleaseBytes)
	osData, err := osrelease.Parse(ctx, r)
	if err != nil {
		return "", fmt.Errorf("unable to parse os-release data %w", err)
	}

	return osData["VERSION_ID"], nil
}

// e.g. "docker.io/library/nginx:1.21.6-patched".
func getRepoNameWithDigest(patchedImageName, imageDigest string) string {
	parts := strings.Split(patchedImageName, "/")
	last := parts[len(parts)-1]
	if idx := strings.IndexRune(last, ':'); idx >= 0 {
		last = last[:idx]
	}
	nameWithDigest := fmt.Sprintf("%s@%s", last, imageDigest)
	return nameWithDigest
}

var validPlatforms = []string{
	"linux/386",
	"linux/amd64",
	"linux/arm",
	"linux/arm/v5",
	"linux/arm/v6",
	"linux/arm/v7",
	"linux/arm64",
	"linux/arm64/v8",
	"linux/ppc64le",
	"linux/s390x",
}

// filterPlatforms filters discovered platforms based on user-specified target platforms.
func filterPlatforms(discoveredPlatforms []types.PatchPlatform, targetPlatforms []string) []types.PatchPlatform {
	var filtered []types.PatchPlatform

	for _, target := range targetPlatforms {
		// Validate platform against allowed list
		if !slices.Contains(validPlatforms, target) {
			log.Warnf("Platform %s is not in the list of valid platforms: %v", target, validPlatforms)
			continue
		}

		targetPlatform, err := platforms.Parse(target)
		if err != nil {
			log.Warnf("Invalid platform format %s: %v", target, err)
			continue
		}
		targetPlatform = platforms.Normalize(targetPlatform)

		for _, discovered := range discoveredPlatforms {
			if platforms.Only(targetPlatform).Match(discovered.Platform) {
				filtered = append(filtered, discovered)
				break
			}
		}
	}

	return filtered
}

func patchMultiPlatformImage(
	ctx context.Context,
	ch chan error,
	image, reportDir, patchedTag, suffix, workingFolder, scanner, format, output, loader string,
	ignoreError, push bool,
	bkOpts buildkit.Opts,
	targetPlatforms []string,
	discoveredPlatforms []types.PatchPlatform,
) error {
	log.Debugf("Handling platform specific errors with ignore-errors=%t", ignoreError)

	var platforms []types.PatchPlatform
	if reportDir != "" {
		// Using report directory - discover platforms from reports
		var err error
		platforms, err = buildkit.DiscoverPlatforms(image, reportDir, scanner)
		if err != nil {
			return err
		}
		if len(platforms) == 0 {
			return fmt.Errorf("no patchable platforms found for image %s", image)
		}
	} else {
		// No report directory - use discovered platforms and filter
		if len(discoveredPlatforms) == 0 {
			return fmt.Errorf("no platforms provided for image %s", image)
		}

		if len(targetPlatforms) > 0 {
			// Filter platforms based on user specification and validate
			patchPlatforms := filterPlatforms(discoveredPlatforms, targetPlatforms)
			if len(patchPlatforms) == 0 {
				return fmt.Errorf("none of the specified platforms %v are available in the image", targetPlatforms)
			}

			// Create a map to track which platforms should be patched
			shouldPatchMap := make(map[string]bool)
			for _, p := range patchPlatforms {
				key := buildkit.PlatformKey(p.Platform)
				shouldPatchMap[key] = true
			}

			// Process all platforms, marking which should be patched vs preserved
			for _, p := range discoveredPlatforms {
				platformCopy := p
				key := buildkit.PlatformKey(p.Platform)
				if shouldPatchMap[key] {
					// Platform should be patched
					platformCopy.ReportFile = ""
					platformCopy.ShouldPreserve = false
				} else {
					// Platform should be preserved
					platformCopy.ShouldPreserve = true
				}
				platforms = append(platforms, platformCopy)
			}

			log.Infof("Patching specified platforms, preserving others")
		} else {
			// Patch all available platforms since no specific platforms were requested
			for _, p := range discoveredPlatforms {
				platformCopy := p
				platformCopy.ReportFile = "" // No vulnerability report, just patch with latest packages
				platformCopy.ShouldPreserve = false
				platforms = append(platforms, platformCopy)
			}
			log.Infof("Patching all available platforms")
		}
	}

	sem := make(chan struct{}, runtime.NumCPU())
	g, gctx := errgroup.WithContext(ctx)

	var mu sync.Mutex
	patchResults := []types.PatchResult{}

	summaryMap := make(map[string]*types.MultiPlatformSummary)

	for _, p := range platforms {
		// rebind
		p := p //nolint
		platformKey := buildkit.PlatformKey(p.Platform)
		g.Go(func() error {
			select {
			case sem <- struct{}{}:
			case <-gctx.Done():
				return gctx.Err()
			}
			defer func() { <-sem }()

			if p.ShouldPreserve {
				// Platform marked for preservation - preserve original
				log.Infof("Platform %s marked for preservation, preserving original in manifest", p.OS+"/"+p.Architecture)

				// Parse the original image reference for the result
				originalRef, err := reference.ParseNormalizedNamed(image)
				if err != nil {
					mu.Lock()
					summaryMap[platformKey] = &types.MultiPlatformSummary{
						Platform: platformKey,
						Status:   "Error",
						Ref:      "",
						Message:  fmt.Sprintf("failed to parse original image reference: %v", err),
					}
					mu.Unlock()
					return err
				}

				// Handle Windows platform without push enabled
				if !push && p.OS == "windows" {
					mu.Lock()
					defer mu.Unlock()
					if !ignoreError {
						summaryMap[platformKey] = &types.MultiPlatformSummary{
							Platform: platformKey,
							Status:   "Error",
							Ref:      originalRef.String() + " (original reference)",
							Message:  "Windows images are not patched",
						}
						return errors.New("cannot save Windows platform image without pushing to registry. Use --push flag to save Windows images to a registry or run with --ignore-errors")
					}
					summaryMap[platformKey] = &types.MultiPlatformSummary{
						Platform: platformKey,
						Status:   "Ignored",
						Ref:      originalRef.String() + " (original reference)",
						Message:  "Windows images are not patched and will be preserved as-is",
					}
					log.Warn("Cannot save Windows platform image without pushing to registry. Use --push flag to save Windows images to a registry.")
					return nil
				}

				// Get the original platform descriptor from the manifest
				originalDesc, err := getPlatformDescriptorFromManifest(image, &p)
				if err != nil {
					mu.Lock()
					summaryMap[platformKey] = &types.MultiPlatformSummary{
						Platform: platformKey,
						Status:   "Error",
						Ref:      "",
						Message:  fmt.Sprintf("failed to get original descriptor for platform %s: %v", p.OS+"/"+p.Architecture, err),
					}
					mu.Unlock()
					return err
				}

				// For platforms without reports, use the original image digest/reference
				result := types.PatchResult{
					OriginalRef: originalRef,
					PatchedRef:  originalRef,
					PatchedDesc: originalDesc,
				}

				mu.Lock()
				patchResults = append(patchResults, result)
				// Add summary entry for unpatched platform
				summaryMap[platformKey] = &types.MultiPlatformSummary{
					Platform: platformKey,
					Status:   "Not Patched",
					Ref:      originalRef.String() + " (original reference)",
					Message:  "Preserved original image (No Scan Report provided for platform)",
				}
				mu.Unlock()
				return nil
			}

			// When no report directory is provided, patch with empty report file
			reportFile := p.ReportFile
			if reportDir == "" {
				reportFile = ""
			}

			res, err := patchSingleArchImage(gctx, ch, image, reportFile, patchedTag, suffix, workingFolder, scanner, format, output, loader, p, ignoreError, push, bkOpts, true)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				status := "Error"
				if ignoreError {
					status = "Ignored"
				}
				summaryMap[platformKey] = &types.MultiPlatformSummary{
					Platform: platformKey,
					Status:   status,
					Ref:      "",
					Message:  err.Error(),
				}
				if !ignoreError {
					return err
				}
				return nil
			} else if res == nil {
				summaryMap[platformKey] = &types.MultiPlatformSummary{
					Platform: platformKey,
					Status:   "Error",
					Ref:      "",
					Message:  "patchSingleArchImage returned nil result",
				}
				return nil
			}

			patchResults = append(patchResults, *res)
			summaryMap[platformKey] = &types.MultiPlatformSummary{
				Platform: platformKey,
				Status:   "Patched",
				Ref:      res.PatchedRef.String(),
				Message:  fmt.Sprintf("Successfully patched image (%s)", p.OS+"/"+p.Architecture),
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	// resolve image ref
	imageName, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return fmt.Errorf("failed to parse reference: %w", err)
	}

	resolvedPatchedTag, err := resolvePatchedTag(imageName, patchedTag, suffix)
	if err != nil {
		return err
	}
	patchedImageName, err := reference.WithTag(imageName, resolvedPatchedTag)
	if err != nil {
		return fmt.Errorf("failed to parse patched image name: %w", err)
	}

	if push {
		err = createMultiPlatformManifest(ctx, patchedImageName, patchResults, image)
		if err != nil {
			return fmt.Errorf("manifest list creation failed: %w", err)
		}
	}

	if !push {
		// Show push commands only for actually patched images (not preserved originals)
		patchedOnlyResults := make([]types.PatchResult, 0)
		for _, result := range patchResults {
			// Only include results where the patched ref differs from original ref
			if result.PatchedRef.String() != result.OriginalRef.String() {
				patchedOnlyResults = append(patchedOnlyResults, result)
			}
		}

		if len(patchedOnlyResults) > 0 {
			log.Info("To push the individual architecture images, run:")
			for _, result := range patchedOnlyResults {
				log.Infof("  docker push %s", result.PatchedRef.String())
			}
			log.Infof("To create and push the multi-platform manifest, run:")

			// Include all platforms (both patched and preserved) in the manifest create command
			refs := make([]string, len(patchResults))
			for i, result := range patchResults {
				if result.PatchedRef.String() != result.OriginalRef.String() {
					// Use the patched reference for actually patched platforms
					refs[i] = result.PatchedRef.String()
				} else {
					// Use the original reference with digest for preserved platforms
					if result.PatchedDesc != nil && result.PatchedDesc.Digest.String() != "" {
						refs[i] = result.OriginalRef.String() + "@" + result.PatchedDesc.Digest.String()
					} else {
						refs[i] = result.OriginalRef.String()
					}
				}
			}

			log.Infof("  docker buildx imagetools create --tag %s %s", patchedImageName.String(), strings.Join(refs, " "))
		} else {
			return fmt.Errorf("no images were processed, check the logs for errors")
		}
	}

	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PLATFORM\tSTATUS\tREFERENCE\tMESSAGE")

	for _, p := range platforms {
		platformKey := buildkit.PlatformKey(p.Platform)
		s := summaryMap[platformKey]
		if s != nil {
			ref := s.Ref
			if ref == "" {
				ref = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Platform, s.Status, ref, s.Message)
		}
	}
	w.Flush()
	log.Info("\nMulti-arch patch summary:\n" + b.String())

	return nil
}

// Gets the descriptor for a specific platform from a multi-arch manifest.
func getPlatformDescriptorFromManifest(imageRef string, targetPlatform *types.PatchPlatform) (*ispec.Descriptor, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("error parsing reference %q: %w", imageRef, err)
	}

	desc, err := remote.Get(ref)
	if err != nil {
		return nil, fmt.Errorf("error fetching descriptor for %q: %w", imageRef, err)
	}

	if !desc.MediaType.IsIndex() {
		return nil, fmt.Errorf("expected multi-platform image but got single-arch image")
	}

	index, err := desc.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("error getting image index: %w", err)
	}

	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("error getting manifest: %w", err)
	}

	// Find the descriptor for the target platform
	for i := range manifest.Manifests {
		m := &manifest.Manifests[i]
		if m.Platform == nil {
			continue
		}

		// Normalize the variant comparison - treat missing variant as empty string
		manifestVariant := m.Platform.Variant
		targetVariant := targetPlatform.Variant
		if m.Platform.Architecture == "arm64" && manifestVariant == "v8" {
			manifestVariant = ""
		}
		if targetPlatform.Architecture == "arm64" && targetVariant == "v8" {
			targetVariant = ""
		}

		if m.Platform.OS == targetPlatform.OS &&
			m.Platform.Architecture == targetPlatform.Architecture &&
			manifestVariant == targetVariant &&
			m.Platform.OSVersion == targetPlatform.OSVersion {
			// Convert the descriptor to the expected format
			ociDesc := &ispec.Descriptor{
				MediaType: string(m.MediaType),
				Size:      m.Size,
				Digest:    digest.Digest(m.Digest.String()),
				Platform: &ispec.Platform{
					OS:           m.Platform.OS,
					Architecture: m.Platform.Architecture,
					Variant:      m.Platform.Variant,
					OSVersion:    m.Platform.OSVersion,
					OSFeatures:   m.Platform.OSFeatures,
				},
				Annotations: m.Annotations,
			}
			return ociDesc, nil
		}
	}

	return nil, fmt.Errorf("platform %s/%s not found in manifest", targetPlatform.OS, targetPlatform.Architecture)
}
