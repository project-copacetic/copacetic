package patch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
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
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/project-copacetic/copacetic/pkg/vex"
	"github.com/quay/claircore/osrelease"
)

const (
	defaultPatchedTagSuffix = "patched"
	copaProduct             = "copa"
	defaultRegistry         = "docker.io"
	defaultTag              = "latest"
)

type BuildOpts struct {
	BkClient                  *client.Client
	SolveOpt                  *client.SolveOpt
	Image                     string
	Ch                        chan error
	ReportFile                string
	WorkingFolder             string
	Updates                   *unversioned.UpdateManifest
	IgnoreError               bool
	Output                    string
	DockerNormalizedImageName reference.Named
	PatchedImageName          string
	Format                    string
}

type BuildStatus struct {
	BuildChannel chan *client.SolveStatus
}

type BuildContext struct {
	Ctx context.Context
}

// Patch command applies package updates to an OCI image given a vulnerability report.
func Patch(ctx context.Context, timeout time.Duration, image, reportFile, patchedTag, workingFolder, scanner, format, output string, ignoreError bool, bkOpts buildkit.Opts) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan error)
	go func() {
		ch <- patchWithContext(timeoutCtx, ch, image, reportFile, patchedTag, workingFolder, scanner, format, output, ignoreError, bkOpts)
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

// patchWithContext patches the user-supplied image, image.
func patchWithContext(ctx context.Context, ch chan error, image, reportFile, userSuppliedPatchTag, workingFolder, scanner, format, output string, ignoreError bool, bkOpts buildkit.Opts) error {
	dockerNormalizedImageName, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return err
	}

	if reference.IsNameOnly(dockerNormalizedImageName) {
		log.Warnf("Image name has no tag or digest, using latest as tag")
		dockerNormalizedImageName = reference.TagNameOnly(dockerNormalizedImageName)
	}

	patchedTag := generatePatchedTag(dockerNormalizedImageName, userSuppliedPatchTag)

	_, err = reference.WithTag(dockerNormalizedImageName, patchedTag)
	if err != nil {
		return fmt.Errorf("%w with patched tag %s", err, patchedTag)
	}

	patchedImageName := fmt.Sprintf("%s:%s", dockerNormalizedImageName.Name(), patchedTag)

	// Ensure working folder exists for call to InstallUpdates
	if workingFolder == "" {
		var err error
		workingFolder, err = os.MkdirTemp("", "copa-*")
		if err != nil {
			return err
		}
		defer removeIfNotDebug(workingFolder)
		if err = os.Chmod(workingFolder, 0o744); err != nil {
			return err
		}
	} else {
		if isNew, err := utils.EnsurePath(workingFolder, 0o744); err != nil {
			log.Errorf("failed to create workingFolder %s", workingFolder)
			return err
		} else if isNew {
			defer removeIfNotDebug(workingFolder)
		}
	}

	var updates *unversioned.UpdateManifest
	// Parse report for update packages
	if reportFile != "" {
		updates, err = report.TryParseScanReport(reportFile, scanner)
		if err != nil {
			return err
		}
		log.Debugf("updates to apply: %v", updates)
	}

	bkClient, err := buildkit.NewClient(ctx, bkOpts)
	if err != nil {
		return err
	}
	defer bkClient.Close()

	pipeR, pipeW := io.Pipe()
	dockerConfig := config.LoadDefaultConfigFile(os.Stderr)
	attachable := []session.Attachable{authprovider.NewDockerAuthProvider(dockerConfig, nil)}
	solveOpt := client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type: client.ExporterDocker,
				Attrs: map[string]string{
					"name": patchedImageName,
				},
				Output: func(_ map[string]string) (io.WriteCloser, error) {
					return pipeW, nil
				},
			},
		},
		Frontend: "",         // i.e. we are passing in the llb.Definition directly
		Session:  attachable, // used for authprovider, sshagentprovider and secretprovider
	}
	solveOpt.SourcePolicy, err = build.ReadSourcePolicy()
	if err != nil {
		return err
	}

	if solveOpt.SourcePolicy != nil {
		switch {
		case strings.Contains(solveOpt.SourcePolicy.Rules[0].Updates.Identifier, "redhat"):
			err = errors.New("RedHat is not supported via source policies due to BusyBox not being in the RHEL repos\n" +
				"Please use a different RPM-based image")
			return err

		case strings.Contains(solveOpt.SourcePolicy.Rules[0].Updates.Identifier, "rockylinux"):
			err = errors.New("RockyLinux is not supported via source policies due to BusyBox not being in the RockyLinux repos\n" +
				"Please use a different RPM-based image")
			return err
		}
	}

	buildChannel := make(chan *client.SolveStatus)
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		err = buildkitBuild(
			BuildContext{ctx},
			&BuildOpts{
				bkClient, &solveOpt, image, ch,
				reportFile, workingFolder, updates, ignoreError,
				output, dockerNormalizedImageName, patchedImageName, format,
			},
			BuildStatus{buildChannel}, updates)
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

	eg.Go(func() error {
		if err := dockerLoad(ctx, pipeR); err != nil {
			return err
		}
		return pipeR.Close()
	})

	return eg.Wait()
}

func buildkitBuild(buildContext BuildContext, buildOpts *BuildOpts, buildStatus BuildStatus, updates *unversioned.UpdateManifest) error {
	_, err := buildOpts.BkClient.Build(buildContext.Ctx, *buildOpts.SolveOpt, copaProduct, func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
		bkConfig, err := buildkit.InitializeBuildkitConfig(ctx, c, buildOpts.DockerNormalizedImageName.String())
		if err != nil {
			return handleError(buildOpts.Ch, err)
		}

		manager, err := resolvePackageManager(buildContext, buildOpts, c, bkConfig, updates)
		if err != nil {
			return handleError(buildOpts.Ch, err)
		}

		return buildReport(ctx, buildOpts.Ch, bkConfig, manager, buildOpts.Updates, buildOpts.IgnoreError, buildOpts.PatchedImageName, buildOpts.Format, buildOpts.Output, buildOpts.ReportFile)
	}, buildStatus.BuildChannel)
	return err
}

func resolvePackageManager(buildContext BuildContext, buildOpts *BuildOpts, client gwclient.Client, config *buildkit.Config, updates *unversioned.UpdateManifest) (pkgmgr.PackageManager, error) {
	var manager pkgmgr.PackageManager
	if buildOpts.ReportFile == "" {
		fileBytes, err := buildkit.ExtractFileFromState(buildContext.Ctx, client, &config.ImageState, "/etc/os-release")
		if err != nil {
			return nil, err
		}

		osType, err := getOSType(buildContext.Ctx, fileBytes)
		if err != nil {
			return nil, err
		}

		osVersion, err := getOSVersion(buildContext.Ctx, fileBytes)
		if err != nil {
			return nil, err
		}
		// get package manager based on os family type
		manager, err = pkgmgr.GetPackageManager(osType, osVersion, config, buildOpts.WorkingFolder)
		if err != nil {
			return nil, err
		}
	} else {
		// get package manager based on os family type
		var err error
		manager, err = pkgmgr.GetPackageManager(updates.Metadata.OS.Type, updates.Metadata.OS.Version, config, buildOpts.WorkingFolder)
		if err != nil {
			return nil, err
		}
	}
	return manager, nil
}

// handleError streamlines error forwarding to error channel and returns the error again for further propagation.
func handleError(ch chan error, err error) (*gwclient.Result, error) {
	ch <- err
	return nil, err
}

// buildReport is an extracted method containing logic to manage the updates and build report.
func buildReport(ctx context.Context, ch chan error, config *buildkit.Config, manager pkgmgr.PackageManager, updates *unversioned.UpdateManifest, ignoreError bool, patchedImageName string, format string, output string, reportFile string) (*gwclient.Result, error) {
	patchedImageState, errPkgs, err := manager.InstallUpdates(ctx, updates, ignoreError)
	if err != nil {
		return handleError(ch, err)
	}
	platform := platforms.Normalize(platforms.DefaultSpec())
	if platform.OS != "linux" {
		platform.OS = "linux"
	}
	def, err := patchedImageState.Marshal(ctx, llb.Platform(platform))
	if err != nil {
		return handleError(ch, fmt.Errorf("unable to get platform from ImageState %w", err))
	}
	res, err := config.Client.Solve(ctx, gwclient.SolveRequest{
		Definition: def.ToPB(),
		Evaluate:   true,
	})
	if err != nil {
		return handleError(ch, err)
	}
	res.AddMeta(exptypes.ExporterImageConfigKey, config.ConfigData)
	// Currently can only validate updates if updating via scanner
	if reportFile != "" {
		validatedManifest := updateManifest(updates, errPkgs)
		// vex document must contain at least one statement
		if output != "" && len(validatedManifest.Updates) > 0 {
			err = vex.TryOutputVexDocument(validatedManifest, manager, patchedImageName, format, output)
			if err != nil {
				return handleError(ch, err)
			}
		}
	}
	return res, nil
}

// updateManifest creates a new manifest with the successfully patched packages.
func updateManifest(updates *unversioned.UpdateManifest, errPkgs []string) *unversioned.UpdateManifest {
	validatedManifest := &unversioned.UpdateManifest{
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
	for _, update := range updates.Updates {
		if !slices.Contains(errPkgs, update.Name) {
			validatedManifest.Updates = append(validatedManifest.Updates, update)
		}
	}
	return validatedManifest
}

func generatePatchedTag(dockerNormalizedImageName reference.Named, userSuppliedPatchTag string) string {
	// officialTag is typically the versioning tag of the image as published in a container registry
	var officialTag string
	var copaTag string

	taggedName, ok := dockerNormalizedImageName.(reference.Tagged)

	if ok {
		officialTag = taggedName.Tag()
	} else {
		log.Warnf("Image name has no tag")
	}

	if userSuppliedPatchTag != "" {
		copaTag = fmt.Sprintf("%s-%s", officialTag, userSuppliedPatchTag)
		return copaTag
	} else if officialTag == "" {
		log.Warnf("No output tag specified for digest-referenced image, defaulting to `%s`", defaultPatchedTagSuffix)
		copaTag = defaultPatchedTagSuffix
		return copaTag
	}

	copaTag = fmt.Sprintf("%s-%s", officialTag, defaultPatchedTagSuffix)
	return copaTag
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
