package generate

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	"github.com/moby/buildkit/util/progress/progressui"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/docker/cli/cli/config"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/quay/claircore/osrelease"
)

const (
	copaProduct = "copa"
	defaultTag  = "latest"
	LINUX       = "linux"
)

// for testing
var (
	bkNewClient = buildkit.NewClient
)

// Generate creates a tar stream containing a Dockerfile and patch layer
func Generate(ctx context.Context, timeout time.Duration, image, reportFile, patchedTag, suffix, workingFolder, scanner string, ignoreErrors bool, outputPath string) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan error)
	go func() {
		ch <- generateWithContext(timeoutCtx, ch, image, reportFile, patchedTag, suffix, workingFolder, scanner, ignoreErrors, outputPath)
	}()

	select {
	case err := <-ch:
		return err
	case <-timeoutCtx.Done():
		<-time.After(1 * time.Second)
		err := fmt.Errorf("generate exceeded timeout %v", timeout)
		log.Error(err)
		return err
	}
}

func generateWithContext(
	ctx context.Context,
	ch chan error,
	image, reportFile, patchedTag, suffix, workingFolder, scanner string,
	ignoreErrors bool,
	outputPath string,
) error {
	// Parse image reference
	imageName, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return fmt.Errorf("failed to parse reference: %w", err)
	}

	// Resolve patched tag
	patchedTag, err = resolvePatchedTag(imageName, patchedTag, suffix)
	if err != nil {
		return err
	}
	patchedImageName := fmt.Sprintf("%s:%s", imageName.Name(), patchedTag)
	log.Infof("Patched image name: %s", patchedImageName)

	// Parse vulnerability report if provided
	var updates *unversioned.UpdateManifest
	if reportFile != "" {
		updates, err = report.TryParseScanReport(reportFile, scanner)
		if err != nil {
			return err
		}
		log.Debugf("updates to apply: %v", updates)
	}

	// Create buildkit client with default options
	bkOpts := buildkit.Opts{
		Addr: "",
	}
	bkClient, err := bkNewClient(ctx, bkOpts)
	if err != nil {
		return err
	}
	defer bkClient.Close()

	// Normalize image reference
	var ref string
	if reference.IsNameOnly(imageName) {
		log.Warnf("Image name has no tag or digest, using latest as tag")
		ref = fmt.Sprintf("%s:%s", imageName.Name(), defaultTag)
	} else {
		ref = imageName.String()
	}

	// Create working folder if needed
	if workingFolder == "" {
		workingFolder, err = os.MkdirTemp("", "copa-*")
		if err != nil {
			return err
		}
		defer func() {
			if log.GetLevel() < log.DebugLevel {
				os.RemoveAll(workingFolder)
			}
		}()
		if err = os.Chmod(workingFolder, 0o744); err != nil {
			return err
		}
	}

	// Extract the patch layer using buildkit
	patchLayer, err := extractPatchLayer(ctx, ch, bkClient, ref, updates, workingFolder, scanner, ignoreErrors)
	if err != nil {
		return err
	}

	// Create tar stream with Dockerfile and patch layer
	return createTarStream(ref, patchedTag, patchLayer, outputPath)
}

func extractPatchLayer(
	ctx context.Context,
	ch chan error,
	bkClient *client.Client,
	image string,
	updates *unversioned.UpdateManifest,
	workingFolder, scanner string,
	ignoreErrors bool,
) ([]byte, error) {
	dockerConfig := config.LoadDefaultConfigFile(os.Stderr)
	cfg := authprovider.DockerAuthProviderConfig{ConfigFile: dockerConfig}
	attachable := []session.Attachable{authprovider.NewDockerAuthProvider(cfg)}

	// Channel to collect the patch layer data
	patchChannel := make(chan []byte, 1)
	buildChannel := make(chan *client.SolveStatus)
	
	eg, ctx := errgroup.WithContext(ctx)

	// Solve options for extracting the diff
	solveOpt := client.SolveOpt{
		Frontend: "",
		Session:  attachable,
		Exports: []client.ExportEntry{
			{
				Type:  client.ExporterTar,
				Attrs: map[string]string{},
				Output: func(_ map[string]string) (io.WriteCloser, error) {
					// Create a buffer to collect the tar data
					buf := &bytes.Buffer{}
					writer := &tarWriter{
						Writer: buf,
						onClose: func() {
							patchChannel <- buf.Bytes()
						},
					}
					return writer, nil
				},
			},
		},
	}

	eg.Go(func() error {
		_, err := bkClient.Build(ctx, solveOpt, copaProduct, func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
			// Get default platform
			platform := platforms.Normalize(platforms.DefaultSpec())
			if platform.OS != LINUX {
				platform.OS = LINUX
			}

			// Initialize buildkit config
			config, err := buildkit.InitializeBuildkitConfig(ctx, c, image, &platform)
			if err != nil {
				ch <- err
				return nil, err
			}

			// Determine OS type and create package manager
			var manager pkgmgr.PackageManager
			if updates == nil {
				// Need to determine OS from image
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

				manager, err = pkgmgr.GetPackageManager(osType, osVersion, config, workingFolder)
				if err != nil {
					ch <- err
					return nil, err
				}
			} else {
				manager, err = pkgmgr.GetPackageManager(updates.Metadata.OS.Type, updates.Metadata.OS.Version, config, workingFolder)
				if err != nil {
					ch <- err
					return nil, err
				}
			}

			// Install updates and get the patched state
			patchedImageState, _, err := manager.InstallUpdates(ctx, updates, ignoreErrors)
			if err != nil {
				ch <- err
				return nil, err
			}

			// Create a diff between original and patched states
			var diffState llb.State
			if config.PatchedConfigData != nil {
				// If already patched, diff against the base to get only new patches
				diffState = llb.Diff(config.ImageState, *patchedImageState)
			} else {
				// First patch, diff original against patched
				diffState = llb.Diff(config.ImageState, *patchedImageState)
			}

			// Export just the diff layer
			def, err := diffState.Marshal(ctx, llb.Platform(platform))
			if err != nil {
				ch <- err
				return nil, err
			}

			res, err := c.Solve(ctx, gwclient.SolveRequest{
				Definition: def.ToPB(),
			})
			if err != nil {
				ch <- err
				return nil, err
			}

			return res, nil
		}, buildChannel)

		return err
	})

	eg.Go(func() error {
		// Display progress
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

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	// Get the patch layer data
	select {
	case patchData := <-patchChannel:
		return patchData, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func createTarStream(image, patchedTag string, patchLayer []byte, outputPath string) error {
	// Open output writer
	var w io.Writer = os.Stdout
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return errors.Wrap(err, "failed to create output file")
		}
		defer f.Close()
		w = f
	}

	tw := tar.NewWriter(w)
	defer tw.Close()

	// Generate Dockerfile
	dockerfile := fmt.Sprintf(`FROM %s
COPY patch/ /
LABEL sh.copa.image.patched="%s"
`, image, time.Now().UTC().Format(time.RFC3339))

	// Write Dockerfile
	dockerfileHeader := &tar.Header{
		Name:    "Dockerfile",
		Mode:    0644,
		Size:    int64(len(dockerfile)),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(dockerfileHeader); err != nil {
		return errors.Wrap(err, "failed to write Dockerfile header")
	}
	if _, err := tw.Write([]byte(dockerfile)); err != nil {
		return errors.Wrap(err, "failed to write Dockerfile content")
	}

	// Extract and rewrite the patch layer tar with proper paths
	tr := tar.NewReader(bytes.NewReader(patchLayer))
	hardlinks := make(map[string]*tar.Header)
	
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "failed to read patch layer tar")
		}

		// Handle hardlinks by converting them to regular files
		if hdr.Typeflag == tar.TypeLink {
			// Store hardlink info for later
			hardlinks[hdr.Name] = hdr
			continue
		}

		// Rewrite the path to be under patch/
		hdr.Name = "patch/" + strings.TrimPrefix(hdr.Name, "/")
		
		// Write the modified header
		if err := tw.WriteHeader(hdr); err != nil {
			return errors.Wrap(err, "failed to write patch file header")
		}

		// Copy the file content
		if hdr.Size > 0 {
			if _, err := io.Copy(tw, tr); err != nil {
				return errors.Wrap(err, "failed to write patch file content")
			}
		}
	}
	
	// Process hardlinks by finding their targets and copying content
	if len(hardlinks) > 0 {
		// Re-read the tar to find hardlink targets
		tr = tar.NewReader(bytes.NewReader(patchLayer))
		fileContents := make(map[string][]byte)
		
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return errors.Wrap(err, "failed to read patch layer tar for hardlinks")
			}
			
			// Store file contents for hardlink targets
			if hdr.Typeflag == tar.TypeReg && hdr.Size > 0 {
				content, err := io.ReadAll(tr)
				if err != nil {
					return errors.Wrap(err, "failed to read file content")
				}
				fileContents[hdr.Name] = content
			}
		}
		
		// Write hardlinks as regular files
		for name, hdr := range hardlinks {
			if content, ok := fileContents[hdr.Linkname]; ok {
				// Convert to regular file
				newHdr := &tar.Header{
					Name:     "patch/" + strings.TrimPrefix(name, "/"),
					Mode:     hdr.Mode,
					Uid:      hdr.Uid,
					Gid:      hdr.Gid,
					Size:     int64(len(content)),
					ModTime:  hdr.ModTime,
					Typeflag: tar.TypeReg,
				}
				
				if err := tw.WriteHeader(newHdr); err != nil {
					return errors.Wrap(err, "failed to write hardlink header")
				}
				
				if _, err := tw.Write(content); err != nil {
					return errors.Wrap(err, "failed to write hardlink content")
				}
			}
		}
	}

	// Flush the tar writer
	if err := tw.Flush(); err != nil {
		return errors.Wrap(err, "failed to flush tar writer")
	}

	log.Info("Successfully generated Docker build context")
	return nil
}

// resolvePatchedTag merges explicit tag & suffix rules
func resolvePatchedTag(imageRef reference.Named, explicitTag, suffix string) (string, error) {
	if explicitTag != "" {
		return explicitTag, nil
	}

	var baseTag string
	if tagged, ok := imageRef.(reference.Tagged); ok {
		baseTag = tagged.Tag()
	}

	if suffix == "" {
		suffix = "patched"
	}

	if baseTag == "" {
		return "", fmt.Errorf("no tag found in image reference %s", imageRef.String())
	}

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
		return "", errors.New("unsupported OS type")
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

// tarWriter wraps an io.Writer and calls onClose when closed
type tarWriter struct {
	io.Writer
	onClose func()
}

func (tw *tarWriter) Close() error {
	if tw.onClose != nil {
		tw.onClose()
	}
	return nil
}