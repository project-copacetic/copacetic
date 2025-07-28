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

	"github.com/distribution/reference"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/docker/cli/cli/config"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

const (
	copaProduct = "copa"
	defaultTag  = "latest"
)

// for testing.
var (
	bkNewClient = buildkit.NewClient
)

// Generate creates a tar stream containing a Dockerfile and patch layer.
func Generate(ctx context.Context, opts *types.Options) error {
	// Extract timeout for context
	timeout := opts.Timeout

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan error)
	go func() {
		ch <- generateWithContext(timeoutCtx, ch, opts)
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
	opts *types.Options,
) error {
	// Extract options
	image := opts.Image
	reportFile := opts.Report
	patchedTag := opts.PatchedTag
	suffix := opts.Suffix
	workingFolder := opts.WorkingFolder
	scanner := opts.Scanner
	ignoreErrors := opts.IgnoreError
	outputPath := opts.OutputContext
	bkOpts := buildkit.Opts{
		Addr:       opts.BkAddr,
		CACertPath: opts.BkCACertPath,
		CertPath:   opts.BkCertPath,
		KeyPath:    opts.BkKeyPath,
	}
	// Parse image reference
	imageName, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return fmt.Errorf("failed to parse reference: %w", err)
	}

	// Resolve patched tag
	patchedTag, err = common.ResolvePatchedTag(imageName, patchedTag, suffix)
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

	// Create buildkit client
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
	workingFolder, _ string,
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
			platform := common.GetDefaultLinuxPlatform()

			// Setup buildkit config and package manager
			var config *buildkit.Config
			var manager pkgmgr.PackageManager
			var osInfo *common.OSInfo

			if updates != nil {
				// Use OS info from report
				osInfo = &common.OSInfo{
					Type:    updates.Metadata.OS.Type,
					Version: updates.Metadata.OS.Version,
				}
			}

			config, manager, err := common.SetupBuildkitConfigAndManager(ctx, c, image, &platform, workingFolder, osInfo)
			if err != nil {
				ch <- err
				return nil, err
			}

			// Install updates and get the patched state
			patchedImageState, _, err := manager.InstallUpdates(ctx, updates, ignoreErrors)
			if err != nil {
				ch <- err
				return nil, err
			}

			// Create a diff between original and patched states
			diffState := llb.Diff(config.ImageState, *patchedImageState)

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

	common.DisplayProgress(ctx, eg, buildChannel)

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

func createTarStream(image, _ string, patchLayer []byte, outputPath string) error {
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
		Mode:    0o600,
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

		// Copy the file content with size limit to prevent decompression bombs
		if hdr.Size > 0 {
			// Limit file size to 1GB to prevent decompression bombs
			const maxFileSize = 1 << 30 // 1GB
			if hdr.Size > maxFileSize {
				return errors.Errorf("file %s exceeds maximum allowed size of 1GB", hdr.Name)
			}
			if _, err := io.CopyN(tw, tr, hdr.Size); err != nil {
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
				// Limit file size to 1GB to prevent decompression bombs
				const maxFileSize = 1 << 30 // 1GB
				if hdr.Size > maxFileSize {
					return errors.Errorf("file %s exceeds maximum allowed size of 1GB", hdr.Name)
				}
				content := make([]byte, hdr.Size)
				if _, err := io.ReadFull(tr, content); err != nil {
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

// tarWriter wraps an io.Writer and calls onClose when closed.
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
