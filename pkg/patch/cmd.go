package patch

import (
	"context"
	"time"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
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
}

func NewPatchCmd() *cobra.Command {
	ua := patchArgs{}
	patchCmd := &cobra.Command{
		Use:     "patch",
		Short:   "Patch container images with upgrade packages specified by a vulnerability report",
		Example: "copa patch -i images/python:3.7-alpine -r trivy.json -t 3.7-alpine-patched",
		RunE: func(_ *cobra.Command, _ []string) error {
			bkopts := buildkit.Opts{
				Addr:       ua.bkOpts.Addr,
				CACertPath: ua.bkOpts.CACertPath,
				CertPath:   ua.bkOpts.CertPath,
				KeyPath:    ua.bkOpts.KeyPath,
			}
			return Patch(context.Background(),
				ua.timeout,
				ua.appImage,
				ua.reportFile,
				ua.patchedTag,
				ua.suffix,
				ua.workingFolder,
				ua.scanner,
				ua.format,
				ua.output,
				ua.ignoreError,
				ua.push,
				bkopts)
		},
	}
	flags := patchCmd.Flags()
	flags.StringVarP(&ua.appImage, "image", "i", "", "Application image name and tag to patch")
	flags.StringVarP(&ua.reportFile, "report", "r", "", "Vulnerability report file path")
	flags.StringVarP(&ua.patchedTag, "tag", "t", "", "Tag for the patched image")
	flags.StringVarP(&ua.suffix, "tag-suffix", "", "patched", "Suffix for the patched image (if no explicit --tag provided)")
	flags.StringVarP(&ua.workingFolder, "working-folder", "w", "", "Working folder, defaults to system temp folder")
	flags.StringVarP(&ua.bkOpts.Addr, "addr", "a", "", "Address of buildkitd service, defaults to local docker daemon with fallback to "+buildkit.DefaultAddr)
	flags.StringVarP(&ua.bkOpts.CACertPath, "cacert", "", "", "Absolute path to buildkitd CA certificate")
	flags.StringVarP(&ua.bkOpts.CertPath, "cert", "", "", "Absolute path to buildkit client certificate")
	flags.StringVarP(&ua.bkOpts.KeyPath, "key", "", "", "Absolute path to buildkit client key")
	flags.DurationVar(&ua.timeout, "timeout", 5*time.Minute, "Timeout for the operation, defaults to '5m'")
	flags.StringVarP(&ua.scanner, "scanner", "s", "trivy", "Scanner used to generate the report, defaults to 'trivy'")
	flags.BoolVar(&ua.ignoreError, "ignore-errors", false, "Ignore errors and continue patching")
	flags.StringVarP(&ua.format, "format", "f", "openvex", "Output format, defaults to 'openvex'")
	flags.StringVarP(&ua.output, "output", "o", "", "Output file path")
	flags.BoolVarP(&ua.push, "push", "p", false, "Push patched image to destination registry")

	if err := patchCmd.MarkFlagRequired("image"); err != nil {
		panic(err)
	}

	return patchCmd
}
