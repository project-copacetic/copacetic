package generate

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type generateArgs struct {
	appImage      string
	reportFile    string
	patchedTag    string
	suffix        string
	workingFolder string
	timeout       time.Duration
	scanner       string
	ignoreError   bool
	outputContext string
}

func NewGenerateCmd() *cobra.Command {
	ga := generateArgs{}
	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a Docker build context tar stream for patching container images",
		Long: `Generate creates a tar stream containing a Dockerfile and patch layer that can be piped to 'docker build'.
This command produces a build context with the patch diff layer and a Dockerfile that applies the patch.`,
		Example: `  # Generate patch context and pipe to docker build
  copa generate -i ubuntu:22.04 -r trivy.json | docker build -t ubuntu:22.04-patched -
  
  # Generate patch context without vulnerability report (update all packages)
  copa generate -i alpine:3.18 | docker build -t alpine:3.18-patched -
  
  # Save context to file
  copa generate -i alpine:3.18 -r scan.json --output-context patch.tar`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if stdout is a TTY when not writing to file
			if ga.outputContext == "" && term.IsTerminal(int(os.Stdout.Fd())) {
				return fmt.Errorf("refusing to write tar stream to terminal. Use --output-context to save to file or redirect stdout")
			}

			return Generate(context.Background(),
				ga.timeout,
				ga.appImage,
				ga.reportFile,
				ga.patchedTag,
				ga.suffix,
				ga.workingFolder,
				ga.scanner,
				ga.ignoreError,
				ga.outputContext,
			)
		},
	}

	flags := generateCmd.Flags()
	flags.StringVarP(&ga.appImage, "image", "i", "", "Application image name and tag to patch")
	flags.StringVarP(&ga.reportFile, "report", "r", "", "Vulnerability report file path (optional)")
	flags.StringVarP(&ga.patchedTag, "tag", "t", "", "Tag for the patched image")
	flags.StringVarP(&ga.suffix, "tag-suffix", "", "patched", "Suffix for the patched image tag if no explicit tag is provided")
	flags.StringVarP(&ga.workingFolder, "working-folder", "w", "", "Working folder, defaults to system temp folder")
	flags.DurationVar(&ga.timeout, "timeout", 5*time.Minute, "Timeout for the operation")
	flags.StringVarP(&ga.scanner, "scanner", "s", "trivy", "Scanner that generated the report")
	flags.BoolVar(&ga.ignoreError, "ignore-errors", false, "Ignore errors during patching")
	flags.StringVar(&ga.outputContext, "output-context", "", "Path to save the generated tar context (instead of stdout)")

	if err := generateCmd.MarkFlagRequired("image"); err != nil {
		panic(err)
	}

	return generateCmd
}