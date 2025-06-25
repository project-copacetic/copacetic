package patch

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"github.com/project-copacetic/copacetic/pkg/buildkit/connhelpers"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/project-copacetic/copacetic/pkg/vex"
	"github.com/quay/claircore/osrelease"

	dockerTypes "github.com/docker/docker/api/types"
	dockerClient "github.com/docker/docker/client"
)

const (
	copaProduct     = "copa"
	defaultRegistry = "docker.io"
	defaultTag      = "latest"
	LINUX           = "linux"
	ARM64           = "arm64"
)

// for testing.
var (
	bkNewClient = buildkit.NewClient
)

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
) error {
	resolver := imagetools.New(imagetools.Opt{
		Auth: config.LoadDefaultConfigFile(os.Stderr),
	})

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

	idxBytes, desc, err := resolver.Combine(ctx, srcRefs, map[exptypes.AnnotationKey]string{}, false)
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
	image, reportPath, patchedTag, suffix, workingFolder, scanner, format, output string,
	ignoreError, push bool,
	bkOpts buildkit.Opts,
) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan error)
	go func() {
		ch <- patchWithContext(timeoutCtx, ch, image, reportPath, patchedTag, suffix, workingFolder, scanner, format, output, ignoreError, push, bkOpts)
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
	image, reportPath, patchedTag, suffix, workingFolder, scanner, format, output string,
	ignoreError, push bool,
	bkOpts buildkit.Opts,
) error {
	// Handle empty report path - single-arch patching without report
	if reportPath == "" {
		platform := types.PatchPlatform{
			Platform: platforms.Normalize(platforms.DefaultSpec()),
		}
		if platform.OS != LINUX {
			platform.OS = LINUX
		}
		result, err := patchSingleArchImage(ctx, ch, image, reportPath, patchedTag, suffix, workingFolder, scanner, format, output, platform, ignoreError, push, bkOpts, false)
		if err == nil && result != nil && result.PatchedRef != nil {
			log.Infof("Patched image (%s): %s\n", platform.OS+"/"+platform.Architecture, result.PatchedRef)
		}
		return err
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
		return patchMultiPlatformImage(ctx, ch, image, reportPath, patchedTag, suffix, workingFolder, scanner, format, output, ignoreError, push, bkOpts)
	}
	// Handle file - single-arch patching
	log.Debugf("Using report file: %s", reportPath)
	platform := types.PatchPlatform{
		Platform: platforms.Normalize(platforms.DefaultSpec()),
	}
	if platform.OS != LINUX {
		platform.OS = LINUX
	}
	result, err := patchSingleArchImage(ctx, ch, image, reportPath, patchedTag, suffix, workingFolder, scanner, format, output, platform, ignoreError, push, bkOpts, false)
	if err == nil && result != nil {
		log.Infof("Patched image (%s): %s\n", platform.OS+"/"+platform.Architecture, result.PatchedRef.String())
	}
	return err
}

func patchSingleArchImage(
	ctx context.Context,
	ch chan error,
	image, reportFile, patchedTag, suffix, workingFolder, scanner, format, output string,
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

	// get the original media type of the image to determine if we should export as OCI or Docker
	mt, err := utils.GetMediaType(ref)
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
			dockerCli, err := newDockerClient()
			if err != nil {
				pipeR.CloseWithError(fmt.Errorf("failed to create docker client for loading: %w", err))
				return fmt.Errorf("failed to create docker client for loading: %w", err)
			}
			defer dockerCli.Close()

			err = dockerLoadWithClient(ctx, dockerCli, pipeR)
			if err != nil {
				pipeR.CloseWithError(fmt.Errorf("dockerLoadWithClient failed: %w", err))
				return fmt.Errorf("dockerLoadWithClient failed: %w", err)
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

	patchedDesc, err := utils.GetImageDescriptor(context.Background(), patchedImageName)
	if err != nil { // dont necessarily need to fail if we can't get the descriptor
		prettyPlatform := platforms.Format(targetPlatform.Platform)
		log.Warnf("failed to get patched image descriptor for platform '%s':  %v", prettyPlatform, err)
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

func newDockerClient() (dockerClient.APIClient, error) {
	hostOpt := func(c *dockerClient.Client) error {
		if os.Getenv(dockerClient.EnvOverrideHost) != "" {
			// Fallback to just keep dockerClient.FromEnv whatever was set from
			return nil
		}
		addr, err := connhelpers.AddrFromDockerContext()
		if err != nil {
			log.WithError(err).Error("Error loading docker context, falling back to env")
			return nil
		}
		return dockerClient.WithHost(addr)(c)
	}

	cli, err := dockerClient.NewClientWithOpts(dockerClient.FromEnv, hostOpt, dockerClient.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}
	log.Debug("Docker client initialized successfully")
	return cli, nil
}

func dockerLoadWithClient(ctx context.Context, cli dockerClient.APIClient, pipeR io.Reader) error {
	log.Debugf("Loading image stream using Docker API client")
	resp, err := cli.ImageLoad(ctx, pipeR, dockerClient.ImageLoadWithQuiet(false))
	if err != nil {
		log.Errorf("Docker API ImageLoad failed: %v", err)
		return fmt.Errorf("docker client ImageLoad: %w", err)
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	lastLine := ""
	for scanner.Scan() {
		line := scanner.Text()
		lastLine = line
		log.Debugf("ImageLoad response stream: %s", line)
	}

	if err := scanner.Err(); err != nil {
		log.Warnf("Error reading ImageLoad response body stream: %v", err)
	}

	if resp.JSON && lastLine != "" {
		var jsonResp struct {
			ErrorResponse *dockerTypes.ErrorResponse `json:"errorResponse"`
			Error         string                     `json:"error"`
		}
		if err := json.Unmarshal([]byte(lastLine), &jsonResp); err == nil {
			if jsonResp.ErrorResponse != nil {
				msg := fmt.Sprintf("ImageLoad reported error: %s", jsonResp.ErrorResponse.Message)
				log.Error(msg)
				return errors.New(msg)
			}
			if jsonResp.Error != "" {
				// Sometimes the error is directly in the 'error' field
				msg := fmt.Sprintf("ImageLoad reported error: %s", jsonResp.Error)
				log.Error(msg)
				return errors.New(msg)
			}
		} else {
			log.Debugf("Final ImageLoad response line (non-JSON or parse error): %s", lastLine)
		}
	} else if lastLine != "" {
		log.Debugf("Final ImageLoad response line (non-JSON): %s", lastLine)
	}

	log.Info("Image loaded successfully via Docker API")
	return nil
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

func patchMultiPlatformImage(
	ctx context.Context,
	ch chan error,
	image, reportDir, patchedTag, suffix, workingFolder, scanner, format, output string,
	ignoreError, push bool,
	bkOpts buildkit.Opts,
) error {
	log.Debugf("Handling platform specific errors with ignore-errors=%t", ignoreError)
	platforms, err := buildkit.DiscoverPlatforms(image, reportDir, scanner)
	if err != nil {
		return err
	}
	if len(platforms) == 0 {
		return fmt.Errorf("no patchable platforms found for image %s", image)
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

			if p.ReportFile == "" {
				// No report for this platform - preserve original
				log.Infof("No report for platform %s, preserving original in manifest", p.OS+"/"+p.Architecture)

				// Handle Windows platform without push enabled
				if !push && p.OS == "windows" {
					if !ignoreError {
						return errors.New("cannot save Windows platform image without pushing to registry. Use --push flag to save Windows images to a registry or run with --ignore-errors")
					}
					log.Warn("Cannot save Windows platform image without pushing to registry. Use --push flag to save Windows images to a registry.")
				}

				// Get the original platform descriptor from the manifest
				originalDesc, err := getPlatformDescriptorFromManifest(image, &p)
				if err != nil {
					return fmt.Errorf("failed to get original descriptor for platform %s: %w", p.OS+"/"+p.Architecture, err)
				}

				// Parse the original image reference for the result
				originalRef, err := reference.ParseNormalizedNamed(image)
				if err != nil {
					return fmt.Errorf("failed to parse original image reference: %w", err)
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
					Error:    "",
				}
				mu.Unlock()
				log.Infof("Preserved original image (%s): %s\n", p.OS+"/"+p.Architecture, originalRef.String())
				return nil
			}

			res, err := patchSingleArchImage(gctx, ch, image, p.ReportFile, patchedTag, suffix, workingFolder, scanner, format, output, p, ignoreError, push, bkOpts, true)
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
					Error:    err.Error(),
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
					Error:    "patchSingleArchImage returned nil result",
				}
				return nil
			}

			patchResults = append(patchResults, *res)
			summaryMap[platformKey] = &types.MultiPlatformSummary{
				Platform: platformKey,
				Status:   "Patched",
				Ref:      res.PatchedRef.String(),
				Error:    "",
			}
			log.Infof("Patched image (%s): %s\n", p.OS+"/"+p.Architecture, res.PatchedRef.String())
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
		err = createMultiPlatformManifest(ctx, patchedImageName, patchResults)
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
			return fmt.Errorf("no patched images were created, check the logs for errors")
		}
	}

	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PLATFORM\tSTATUS\tREFERENCE\tERROR")

	for _, p := range platforms {
		platformKey := buildkit.PlatformKey(p.Platform)
		s := summaryMap[platformKey]
		if s != nil {
			ref := s.Ref
			if ref == "" {
				ref = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Platform, s.Status, ref, s.Error)
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
			}
			return ociDesc, nil
		}
	}

	return nil, fmt.Errorf("platform %s/%s not found in manifest", targetPlatform.OS, targetPlatform.Architecture)
}
