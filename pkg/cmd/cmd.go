package cmd

import (
	"context"
	"errors"
	"time"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/bulk"
	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/project-copacetic/copacetic/pkg/types"
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
	report        string
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
			opts := &types.Options{
				Image:         ua.appImage,
				Report:        ua.report,
				PatchedTag:    ua.patchedTag,
				Suffix:        ua.suffix,
				WorkingFolder: ua.workingFolder,
				Timeout:       ua.timeout,
				Scanner:       ua.scanner,
				IgnoreError:   ua.ignoreError,
				Format:        ua.format,
				Output:        ua.output,
				BkAddr:        ua.bkOpts.Addr,
				BkCACertPath:  ua.bkOpts.CACertPath,
				BkCertPath:    ua.bkOpts.CertPath,
				BkKeyPath:     ua.bkOpts.KeyPath,
				Push:          ua.push,
				Platforms:     ua.platform,
				Loader:        ua.loader,
				ConfigFile:    ua.configFile,
			}

			if ua.configFile == "" && ua.appImage == "" {
				return errors.New("either --config or --image must be provided")
			}

			// bulk patch
			if ua.configFile != "" {
				if ua.appImage != "" || ua.report != "" || ua.patchedTag != "" {
					return errors.New("--config cannot be used with --image, --report, or --tag")
				}

				log.Info("Starting in bulk image patching mode...")

				return bulk.PatchFromConfig(context.Background(), ua.configFile, opts)
			}
			if ua.appImage == "" {
				return errors.New("--image is required when not using --config")
			}
			log.Info("Starting in single image patching mode...")
			return patch.Patch(context.Background(), opts)
		},
	}
	flags := patchCmd.Flags()
	flags.StringVar(&ua.configFile, "config", "", "Path to a bulk patch YAML config file. If used, --image and --report are ignored.")
	flags.StringVarP(&ua.appImage, "image", "i", "", "Application image name and tag to patch")
	flags.StringVarP(&ua.report, "report", "r", "", "Vulnerability report file or directory path")
	flags.StringVarP(&ua.patchedTag, "tag", "t", "", "Tag for the patched image")
	flags.StringVarP(&ua.suffix, "tag-suffix", "", "patched", "Suffix for the patched image (if no explicit --tag provided)")
	flags.StringVarP(&ua.workingFolder, "working-folder", "w", "", "Working folder, defaults to system temp folder")
	flags.StringVarP(&ua.bkOpts.Addr, "addr", "a", "", "Address of buildkitd service, defaults to local docker daemon with fallback to "+buildkit.DefaultAddr)
	flags.StringVarP(&ua.bkOpts.CACertPath, "cacert", "", "", "Absolute path to buildkitd CA certificate")
	flags.StringVarP(&ua.bkOpts.CertPath, "cert", "", "", "Absolute path to buildkit client certificate")
	flags.StringVarP(&ua.bkOpts.KeyPath, "key", "", "", "Absolute path to buildkit client key")
	flags.DurationVar(&ua.timeout, "timeout", 5*time.Minute, "Timeout for the operation, defaults to '5m'")
	flags.StringVarP(&ua.scanner, "scanner", "s", "trivy", "Scanner used to generate the report, defaults to 'trivy'")
	flags.BoolVar(&ua.ignoreError, "ignore-errors", false, "Ignore errors and continue patching (for single-platform: continue with other packages; for multi-platform: continue with other platforms)")
	flags.StringVarP(&ua.format, "format", "f", "openvex", "Output format, defaults to 'openvex'")
	flags.StringVarP(&ua.output, "output", "o", "", "Output file path")
	flags.BoolVarP(&ua.push, "push", "p", false, "Push patched image to destination registry")
	flags.StringSliceVar(&ua.platform, "platform", nil,
		"Target platform(s) for multi-arch images when no report directory is provided (e.g., linux/amd64,linux/arm64). "+
			"Valid platforms: linux/amd64, linux/arm64, linux/riscv64, linux/ppc64le, linux/s390x, linux/386, linux/arm/v7, linux/arm/v6. "+
			"If platform flag is used, only specified platforms are patched and the rest are preserved. If not specified, all platforms present in the image are patched.")
	flags.StringVarP(&ua.loader, "loader", "l", "", "Loader to use for loading images. Options: 'docker', 'podman', or empty for auto-detection based on buildkit address")

	return patchCmd
}
