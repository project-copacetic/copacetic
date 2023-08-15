// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package patch

import (
	"os"
	"os/signal"
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

func NewPatchCmd() *cobra.Command {
	ua := Config{}
	patchCmd := &cobra.Command{
		Use:     "patch",
		Short:   "Patch container images with upgrade packages specified by a vulnerability report",
		Example: "copa patch -i images/python:3.7-alpine -r trivy.json -t 3.7-alpine-patched",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer cancel()
			return Patch(ctx, &ua)
		},
	}
	flags := patchCmd.Flags()
	flags.StringVarP(&ua.Image, "image", "i", "", "Application image name and tag to patch")
	flags.StringVarP(&ua.ReportFile, "report", "r", "", "Vulnerability report file path")
	flags.StringVarP(&ua.PatchedTag, "tag", "t", "", "Tag for the patched image")
	flags.StringVarP(&ua.WorkDir, "working-folder", "w", "", "Working folder, defaults to system temp folder")
	flags.StringVarP(&ua.BuildkitAddr, "addr", "a", "", "Address of buildkitd service, defaults to local docker daemon with fallback to "+buildkit.DefaultAddr)
	flags.DurationVar(&ua.Timeout, "timeout", 5*time.Minute, "Timeout for the operation, defaults to '5m'")
	flags.StringSliceVar(&ua.CacheFrom, "cache-from", nil, "Cache import sources")
	flags.StringSliceVar(&ua.CacheTo, "cache-to", nil, "Cache export destination")

	if err := patchCmd.MarkFlagRequired("image"); err != nil {
		panic(err)
	}
	if err := patchCmd.MarkFlagRequired("report"); err != nil {
		panic(err)
	}

	return patchCmd
}
