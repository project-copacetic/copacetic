// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package patch

import (
	"context"
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultBuildkitAddr = "unix:///run/buildkit/buildkitd.sock"
)

type patchArgs struct {
	appImage      string
	reportFile    string
	patchedTag    string
	workingFolder string
	buildkitAddr  string
	timeout       time.Duration
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
				ua.workingFolder)
		},
	}
	flags := patchCmd.Flags()
	flags.StringVarP(&ua.appImage, "image", "i", "", "Application image name and tag to patch")
	flags.StringVarP(&ua.reportFile, "report", "r", "", "Vulnerability report file path")
	flags.StringVarP(&ua.patchedTag, "tag", "t", "", "Tag for the patched image")
	flags.StringVarP(&ua.workingFolder, "working-folder", "w", "", "Working folder, defaults to system temp folder")
	flags.StringVarP(&ua.buildkitAddr, "addr", "a", defaultBuildkitAddr, "Address of buildkitd service, defaults to local buildkitd.sock")
	flags.DurationVar(&ua.timeout, "timeout", 5*time.Minute, "Timeout for the operation, defaults to '5m'")

	if err := patchCmd.MarkFlagRequired("image"); err != nil {
		panic(err)
	}
	if err := patchCmd.MarkFlagRequired("report"); err != nil {
		panic(err)
	}

	return patchCmd
}
