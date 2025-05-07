package patch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/containerd/platforms"
	"github.com/docker/buildx/build"
	"github.com/docker/cli/cli/config"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"

	"github.com/distribution/reference"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	"github.com/moby/buildkit/util/progress/progressui"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/project-copacetic/copacetic/pkg/vex"
	"github.com/quay/claircore/osrelease"
)

const (
	copaProduct     = "copa"
	defaultRegistry = "docker.io"
	defaultTag      = "latest"
)

// for testing.
var (
	bkNewClient = buildkit.NewClient
)

type archDigest struct {
	tag    string
	digest string
	plat   types.PatchPlatform
}

// archTag returns "patched-arm64" or "patched-arm-v7" etc.
func archTag(base, arch, variant string) string {
	if variant != "" {
		return fmt.Sprintf("%s-%s-%s", base, arch, variant)
	}
	return fmt.Sprintf("%s-%s", base, arch)
}

// dockerImageDigest returns the image digest for a given image name.
// It uses the "docker image inspect" command to get the digest.
func dockerImageDigest(img string) (string, error) {
	out, err := exec.Command("docker", "image", "inspect", "--format={{index .Id}}", img).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(strings.TrimSpace(string(out)), "sha256:"), nil
}

// createManifestCLI creates a manifest list for the given image and final tag.
func createManifestCLI(ctx context.Context, image string, finalTag string, items []archDigest) error {
	ref, _ := reference.ParseNormalizedNamed(image)
	repo := ref.Name()
	args := []string{"buildx", "imagetools", "create", "--tag", fmt.Sprintf("%s:%s", repo, finalTag)}
	for i := range items {
		ref := fmt.Sprintf("%s@sha256:%s", items[i].tag, items[i].digest)
		args = append(args, ref)
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
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
	image, reportFile, reportDirectory, platformSpecificErrors, patchedTag, suffix, workingFolder, scanner, format, output string,
	ignoreError, push bool,
	bkOpts buildkit.Opts,
) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan error)
	go func() {
		ch <- patchWithContext(timeoutCtx, ch, image, reportFile, reportDirectory, platformSpecificErrors, patchedTag, suffix, workingFolder, scanner, format, output, ignoreError, push, bkOpts)
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
	image, reportFile, reportDirectory, platformSpecificErrors, patchedTag, suffix, workingFolder, scanner, format, output string,
	ignoreError, push bool,
	bkOpts buildkit.Opts,
) error {
	log.Debugf("Handling platform specific errors with %s", platformSpecificErrors)
	if reportFile != "" && reportDirectory != "" {
		return fmt.Errorf("both report file and directory provided, please provide only one")
	}

	// try report file
	if reportFile != "" {
		// check if reportFile exists
		if _, err := os.Stat(reportFile); os.IsNotExist(err) {
			return fmt.Errorf("report file %s does not exist", reportFile)
		}
		// check if reportFile is a file
		f, err := os.Stat(reportFile)
		if err != nil {
			// handle common errors
			if os.IsNotExist(err) {
				return fmt.Errorf("report file %s does not exist", reportFile)
			}
			return fmt.Errorf("failed to stat report file %s: %w", reportFile, err)
		}
		if f.IsDir() {
			return fmt.Errorf("report file %s is a directory, please provide a file", reportFile)
		}
		log.Debugf("Using report file: %s", reportFile)
		platform := types.PatchPlatform{
			Platform: platforms.Normalize(platforms.DefaultSpec()),
		}
		if platform.OS != "linux" {
			platform.OS = "linux"
		}
		_, err = patchSingleArchImage(ctx, ch, image, reportFile, patchedTag, suffix, workingFolder, scanner, format, output, platform, ignoreError, push, bkOpts, false)
		return err
	} else if reportDirectory == "" && reportFile == "" {
		platform := types.PatchPlatform{
			Platform: platforms.Normalize(platforms.DefaultSpec()),
		}
		_, err := patchSingleArchImage(ctx, ch, image, reportFile, patchedTag, suffix, workingFolder, scanner, format, output, platform, ignoreError, push, bkOpts, false)
		return err
	}

	// must be dealing with a directory
	f, err := os.Stat(reportDirectory)
	if err != nil {
		return err
	}
	if !f.IsDir() {
		return fmt.Errorf("provided report directory path %s is not a directory", reportDirectory)
	}

	return patchMultiArchImage(ctx, ch, platformSpecificErrors, image, reportDirectory, patchedTag, suffix, workingFolder, scanner, format, output, ignoreError, push, bkOpts)
}

func patchSingleArchImage(
	ctx context.Context,
	ch chan error,
	image, reportFile, patchedTag, suffix, workingFolder, scanner, format, output string,
	//nolint:gocritic
	targetPlatform types.PatchPlatform,
	ignoreError, push bool,
	bkOpts buildkit.Opts,
	multiArch bool,
) (*types.PatchResult, error) {
	if reportFile == "" && output != "" {
		log.Warn("No vulnerability report was provided, so no VEX output will be generated.")
	}

	// if the target platform is different from the host platform, we need to check if emulation is enabled
	osEqual := platforms.DefaultSpec().OS == targetPlatform.OS
	archEqual := platforms.DefaultSpec().Architecture == targetPlatform.Architecture
	if osEqual && archEqual {
		log.Debugf("Host platform %+v matches target platform %+v", platforms.DefaultSpec(), targetPlatform)
	} else {
		log.Debugf("Host platform %+v does not match target platform %+v", platforms.DefaultSpec(), targetPlatform)
		// check if emulation is enabled

		if emulationEnabled := buildkit.QemuAvailable(&targetPlatform); !emulationEnabled {
			return nil, fmt.Errorf("emulation is not enabled for platform %s", targetPlatform.OS+"/"+targetPlatform.Architecture)
		}
		log.Debugf("Emulation is enabled for platform %+v", targetPlatform)
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
	if multiArch {
		patchedTag = archTag(patchedTag, targetPlatform.Architecture, targetPlatform.Variant)
	}
	patchedImageName := fmt.Sprintf("%s:%s", imageName.Name(), patchedTag)

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

	pipeR, pipeW := io.Pipe()
	dockerConfig := config.LoadDefaultConfigFile(os.Stderr)
	cfg := authprovider.DockerAuthProviderConfig{ConfigFile: dockerConfig}
	attachable := []session.Attachable{authprovider.NewDockerAuthProvider(cfg)}

	// create solve options based on whether were pushing to registry or loading to docker
	solveOpt := client.SolveOpt{
		Frontend: "",         // i.e. we are passing in the llb.Definition directly
		Session:  attachable, // used for authprovider, sshagentprovider and secretprovider
	}

	// set the export options based on push flag
	if push {
		solveOpt.Exports = []client.ExportEntry{
			{
				Type: client.ExporterImage,
				Attrs: map[string]string{
					"name": patchedImageName,
					"push": "true",
				},
			},
		}
	} else {
		solveOpt.Exports = []client.ExportEntry{
			{
				Type: client.ExporterDocker,
				Attrs: map[string]string{
					"name": patchedImageName,
				},
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
	patchedImageDigest := make(chan string, 1)
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
		if err == nil && solveResponse != nil && reportFile != "" && validatedManifest != nil {
			digest := solveResponse.ExporterResponse[exptypes.ExporterImageDigestKey]
			patchedImageDigest <- digest
			if reportFile != "" && validatedManifest != nil {
				nameDigestOrTag := getRepoNameWithDigest(patchedImageName, digest)
				// vex document must contain at least one statement
				if output != "" && len(validatedManifest.Updates) > 0 {
					if err := vex.TryOutputVexDocument(validatedManifest, pkgType, nameDigestOrTag, format, output); err != nil {
						ch <- err
						return err
					}
				}
			}
		}
		// make sure at least patchedImageDigest gets closed
		if patchedImageDigest != nil {
			close(patchedImageDigest)
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
			if err := dockerLoad(ctx, pipeR); err != nil {
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

	// Get the solve response from channel
	digest := <-patchedImageDigest
	if digest == "" && !push {
		if d, err := dockerImageDigest(patchedImageName); err == nil {
			digest = d
		} else {
			log.Errorf("failed to get image digest: %v", err)
		}
	}

	return &types.PatchResult{
		OriginalImage: image,
		PatchedImage:  patchedImageName,
		Digest:        digest,
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

func dockerLoad(ctx context.Context, pipeR io.Reader) error {
	cmd := exec.CommandContext(ctx, "docker", "load")
	cmd.Stdin = pipeR

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	// Pipe run errors to WarnLevel since execution continues asynchronously
	// Caller should log a separate ErrorLevel on completion based on err
	go utils.LogPipe(stderr, log.WarnLevel)
	go utils.LogPipe(stdout, log.InfoLevel)

	return cmd.Run()
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

func patchMultiArchImage(
	ctx context.Context,
	ch chan error,
	platformSpecificErrors, image, reportDir, patchedTag, suffix, workingFolder, scanner, format, output string,
	ignoreError, push bool,
	bkOpts buildkit.Opts,
) error {
	platforms, err := buildkit.DiscoverPlatforms(image, reportDir, scanner)
	if err != nil {
		return err
	}
	if len(platforms) == 0 {
		return fmt.Errorf("no patchable platforms found for image %s", image)
	}

	maxParallel := runtime.NumCPU()
	sem := make(chan struct{}, maxParallel)
	g, gctx := errgroup.WithContext(ctx)

	var mu sync.Mutex
	archDigests := []archDigest{}

	handlePlatformErr := func(p types.PatchPlatform, err error) error {
		switch platformSpecificErrors {
		case "ignore":
			return nil
		case "skip":
			log.Warnf("Ignoring error for platform %s: %v", p.OS+"/"+p.Architecture, err)
			return nil
		default:
			return fmt.Errorf("platform %s failed: %w", p.OS+"/"+p.Architecture, err)
		}
	}

	for _, p := range platforms {
		g.Go(func() error {
			sem <- struct{}{}
			defer func() { <-sem }()

			res, err := patchSingleArchImage(gctx, ch, image, p.ReportFile, patchedTag, suffix, workingFolder, scanner, format, output, p, ignoreError, push, bkOpts, true)
			if err != nil {
				return handlePlatformErr(p, err)
			}

			mu.Lock()
			archDigests = append(archDigests, archDigest{tag: res.PatchedImage, digest: strings.TrimPrefix(res.Digest, "sha256:"), plat: p})
			mu.Unlock()
			log.Infof("Patched image (%s): %s\n", p.OS+"/"+p.Architecture, res.PatchedImage)
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

	resolvedTag, err := resolvePatchedTag(imageName, patchedTag, suffix)
	if err != nil {
		return err
	}

	if push {
		if err := createManifestCLI(ctx, image, resolvedTag, archDigests); err != nil {
			return fmt.Errorf("manifest list creation failed: %w", err)
		}
	}
	return nil
}
