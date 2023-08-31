// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

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
	workingFolder string
	buildkitAddr  string
	timeout       time.Duration
	ignoreError   bool
	format        string
	output        string
}

func NewPatchCmd() *cobra.Command {
	ua := patchArgs{}
	patchCmd := &cobra.Command{
		Use:     "patch",
		Short:   "Patch container images with upgrade packages specified by a vulnerability report",
		Example: "copa patch -i images/python:3.7-alpine -r trivy.json -t 3.7-alpine-patched",
		RunE: func(cmd *cobra.Command, args []string) error {
			return Patch(context.Background(),
				ua.timeout,
				ua.buildkitAddr,
				ua.appImage,
				ua.reportFile,
				ua.patchedTag,
				ua.workingFolder,
				ua.format,
				ua.output,
				ua.ignoreError)
		},
	}
	flags := patchCmd.Flags()
	flags.StringVarP(&ua.appImage, "image", "i", "", "Application image name and tag to patch")
	flags.StringVarP(&ua.reportFile, "report", "r", "", "Vulnerability report file path")
	flags.StringVarP(&ua.patchedTag, "tag", "t", "", "Tag for the patched image")
	flags.StringVarP(&ua.workingFolder, "working-folder", "w", "", "Working folder, defaults to system temp folder")
	flags.StringVarP(&ua.buildkitAddr, "addr", "a", "", "Address of buildkitd service, defaults to local docker daemon with fallback to "+buildkit.DefaultAddr)
	flags.DurationVar(&ua.timeout, "timeout", 5*time.Minute, "Timeout for the operation, defaults to '5m'")
	flags.BoolVar(&ua.ignoreError, "ignore-errors", false, "Ignore errors and continue patching")
	flags.StringVarP(&ua.format, "format", "f", "openvex", "Output format, defaults to 'openvex'")
	flags.StringVarP(&ua.output, "output", "o", "", "Output file path")

	if err := patchCmd.MarkFlagRequired("image"); err != nil {
		panic(err)
	}
	if err := patchCmd.MarkFlagRequired("report"); err != nil {
		panic(err)
	}

	return patchCmd
}
