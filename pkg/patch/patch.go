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
	copaProduct     = "copa"
	defaultRegistry = "docker.io"
	defaultTag      = "latest"
)

// Patch command applies package updates to an OCI image given a vulnerability report.
func Patch(ctx context.Context, timeout time.Duration, image, reportFile, patchedTag, suffix, workingFolder, scanner, format, output string, ignoreError, push bool, bkOpts buildkit.Opts) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan error)
	go func() {
		ch <- patchWithContext(timeoutCtx, ch, image, reportFile, patchedTag, suffix, workingFolder, scanner, format, output, ignoreError, push, bkOpts)
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

func patchWithContext(ctx context.Context, ch chan error, image, reportFile, patchedTag, suffix, workingFolder, scanner, format, output string, ignoreError, push bool, bkOpts buildkit.Opts) error {
	if reportFile == "" && output != "" {
		log.Warn("No vulnerability report was provided, so no VEX output will be generated.")
	}

	// parse the image reference
	imageName, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return fmt.Errorf("failed to parse reference: %w", err)
	}

	// resolve final patched tag
	patchedTag, err = resolvePatchedTag(imageName, patchedTag, suffix)
	if err != nil {
		return err
	}

	// create the patched image name
	_, err = reference.WithTag(imageName, patchedTag)
	if err != nil {
		return fmt.Errorf("invalid patched tag: %w with patched tag %s", err, patchedTag)
	}
	patchedImageName := fmt.Sprintf("%s:%s", imageName.Name(), patchedTag)

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

		case strings.Contains(solveOpt.SourcePolicy.Rules[0].Updates.Identifier, "alma"):
			err = errors.New("AlmaLinux is not supported via source policies due to BusyBox not being in the AlmaLinux repos\n" +
				"Please use a different RPM-based image")
			return err
		}
	}

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

			platform := platforms.Normalize(platforms.DefaultSpec())
			if platform.OS != "linux" {
				platform.OS = "linux"
			}

			def, err := patchedImageState.Marshal(ctx, llb.Platform(platform))
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

			res.AddMeta(exptypes.ExporterImageConfigKey, config.ConfigData)

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
		if reportFile != "" && validatedManifest != nil {
			digest := solveResponse.ExporterResponse[exptypes.ExporterImageDigestKey]
			nameDigestOrTag := getRepoNameWithDigest(patchedImageName, digest)
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
			if err := dockerLoad(ctx, pipeR); err != nil {
				return err
			}
			return pipeR.Close()
		})
	} else {
		// when pushing, we need to close the pipe reader since we wont use it
		go func() {
			pipeR.Close()
		}()
	}

	err = eg.Wait()

	return err
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
