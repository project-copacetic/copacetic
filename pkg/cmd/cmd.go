package cmd

import (
	"context"
	"errors"
	"time"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/bulk"
	"github.com/project-copacetic/copacetic/pkg/patch"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	// Register connection helpers for buildkit.
	_ "github.com/moby/buildkit/client/connhelper/dockercontainer"
	_ "github.com/moby/buildkit/client/connhelper/kubepod"
	_ "github.com/moby/buildkit/client/connhelper/nerdctlcontainer"
	_ "github.com/moby/buildkit/client/connhelper/podmancontainer"
	_ "github.com/moby/buildkit/client/connhelper/ssh"
)

type patchArgs struct {
	appImage      string
	reportFile    string
	patchedTag    string
	suffix        string
	workingFolder string
	timeout       time.Duration
	scanner       string
	ignoreError   bool
	format        string
	output        string
	bkOpts        buildkit.Opts
	push          bool
	platform      []string
	loader        string
	configFile    string
}

func NewPatchCmd() *cobra.Command {
	ua := patchArgs{}
	patchCmd := &cobra.Command{
		Use:   "patch",
		Short: "Patch container images with upgrade packages specified by a vulnerability report or by comprehensive update",
		Example: `  copa patch -i images/python:3.7-alpine -r trivy.json
  copa patch --config copa-bulk-config.yaml --push`,
		RunE: func(_ *cobra.Command, _ []string) error {
			if ua.configFile == "" && ua.appImage == "" {
				return errors.New("either --config or --image must be provided")
			}

			// bulk patch
			if ua.configFile != "" {
				if ua.appImage != "" || ua.reportFile != "" || ua.patchedTag != "" {
					return errors.New("--config cannot be used with --image, --report, or --tag")
				}

				log.Info("Starting in bulk image patching mode...")

				bkopts := buildkit.Opts{
					Addr:       ua.bkOpts.Addr,
					CACertPath: ua.bkOpts.CACertPath,
					CertPath:   ua.bkOpts.CertPath,
					KeyPath:    ua.bkOpts.KeyPath,
				}
				bulkOpts := &bulk.OrchestratorOptions{
					Timeout:       ua.timeout.String(),
					Push:          ua.push,
					IgnoreErrors:  ua.ignoreError,
					WorkingFolder: ua.workingFolder,
					Scanner:       ua.scanner,
					Format:        ua.format,
					Output:        ua.output,
					Loader:        ua.loader,
					BKOOpts:       bkopts,
				}

				return bulk.PatchFromConfig(context.Background(), ua.configFile, bulkOpts)
			}
			if ua.appImage == "" {
				return errors.New("--image is required when not using --config")
			}
			log.Info("Starting in single image patching mode...")

			bkopts := buildkit.Opts{
				Addr:       ua.bkOpts.Addr,
				CACertPath: ua.bkOpts.CACertPath,
				CertPath:   ua.bkOpts.CertPath,
				KeyPath:    ua.bkOpts.KeyPath,
			}
			return patch.Patch(context.Background(),
				ua.timeout,
				ua.appImage,
				ua.reportFile,
				ua.patchedTag,
				ua.suffix,
				ua.workingFolder,
				ua.scanner,
				ua.format,
				ua.output,
				ua.loader,
				ua.ignoreError,
				ua.push,
				ua.platform,
				bkopts)
		},
	}
	flags := patchCmd.Flags()
	flags.StringVar(&ua.configFile, "config", "", "Path to a bulk patch YAML config file. If used, --image and --report are ignored.")
	flags.StringVarP(&ua.appImage, "image", "i", "", "Application image name and tag to patch")
	flags.StringVarP(&ua.reportFile, "report", "r", "", "Vulnerability report file or directory path")
	flags.StringVarP(&ua.patchedTag, "tag", "t", "", "Tag for the patched image")
	flags.StringVarP(&ua.suffix, "tag-suffix", "", "patched", "Suffix for the patched image (if no explicit --tag provided)")
	flags.StringVarP(&ua.workingFolder, "working-folder", "w", "", "Working folder, defaults to system temp folder")
	flags.StringVarP(&ua.bkOpts.Addr, "addr", "a", "", "Address of buildkitd service, defaults to local docker daemon with fallback to "+buildkit.DefaultAddr)
	flags.StringVar(&ua.bkOpts.CACertPath, "cacert", "", "Absolute path to buildkitd CA certificate")
	flags.StringVar(&ua.bkOpts.CertPath, "cert", "", "Absolute path to buildkitd client certificate")
	flags.StringVar(&ua.bkOpts.KeyPath, "key", "", "Absolute path to buildkitd client key")
	flags.DurationVar(&ua.timeout, "timeout", 15*time.Minute, "Timeout for the entire operation, defaults to '15m'")
	flags.StringVarP(&ua.scanner, "scanner", "s", "trivy", "Scanner used to generate reports")
	flags.BoolVar(&ua.ignoreError, "ignore-errors", false, "Ignore errors during a patch operation and continue with other tasks")
	flags.StringVarP(&ua.format, "format", "f", "openvex", "Output format for VEX documents")
	flags.StringVarP(&ua.output, "output", "o", "", "Output file path for VEX documents")
	flags.BoolVarP(&ua.push, "push", "p", false, "Push patched image(s) to the destination registry")
	flags.StringSliceVar(&ua.platform, "platform", nil,
		"Target platform(s) for multi-arch images when no report directory is provided (e.g., linux/amd64,linux/arm64). "+
			"Valid platforms: linux/amd64, linux/arm64, linux/riscv64, linux/ppc64le, linux/s390x, linux/386, linux/arm/v7, linux/arm/v6. "+
			"If platform flag is used, only specified platforms are patched and the rest are preserved. If not specified, all platforms present in the image are patched.")
	flags.StringVar(&ua.loader, "loader", "", "Specify container image loader: docker or podman. Auto-detects if not set.")

	return patchCmd
}
