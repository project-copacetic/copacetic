package generate

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	// Register connection helpers for buildkit.
	_ "github.com/moby/buildkit/client/connhelper/dockercontainer"
	_ "github.com/moby/buildkit/client/connhelper/kubepod"
	_ "github.com/moby/buildkit/client/connhelper/nerdctlcontainer"
	_ "github.com/moby/buildkit/client/connhelper/podmancontainer"
	_ "github.com/moby/buildkit/client/connhelper/ssh"
	"github.com/moby/buildkit/util/progress/progressui"
)

type generateArgs struct {
	appImage          string
	report            string
	patchedTag        string
	suffix            string
	workingFolder     string
	timeout           time.Duration
	scanner           string
	ignoreError       bool
	outputContext     string
	format            string
	output            string
	bkOpts            buildkit.Opts
	platform          []string
	loader            string
	pkgTypes          string
	libraryPatchLevel string
	progress          string
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
		RunE: func(_ *cobra.Command, _ []string) error {
			// Check if stdout is a TTY when not writing to file
			if ga.outputContext == "" && term.IsTerminal(int(os.Stdout.Fd())) {
				return fmt.Errorf("refusing to write tar stream to terminal. Use --output-context to save to file or redirect stdout")
			}

			// Validate library patch level
			if err := validateLibraryPatchLevel(ga.libraryPatchLevel, ga.pkgTypes); err != nil {
				return err
			}

			opts := &types.Options{
				Image:             ga.appImage,
				Report:            ga.report,
				PatchedTag:        ga.patchedTag,
				Suffix:            ga.suffix,
				WorkingFolder:     ga.workingFolder,
				Timeout:           ga.timeout,
				Scanner:           ga.scanner,
				IgnoreError:       ga.ignoreError,
				OutputContext:     ga.outputContext,
				Format:            ga.format,
				Output:            ga.output,
				BkAddr:            ga.bkOpts.Addr,
				BkCACertPath:      ga.bkOpts.CACertPath,
				BkCertPath:        ga.bkOpts.CertPath,
				BkKeyPath:         ga.bkOpts.KeyPath,
				Platforms:         ga.platform,
				Loader:            ga.loader,
				PkgTypes:          ga.pkgTypes,
				LibraryPatchLevel: ga.libraryPatchLevel,
				Progress:          progressui.DisplayMode(ga.progress),
			}
			return Generate(context.Background(), opts)
		},
	}

	flags := generateCmd.Flags()
	flags.StringVarP(&ga.appImage, "image", "i", "", "Application image name and tag to patch")
	flags.StringVarP(&ga.report, "report", "r", "", "Vulnerability report file path (optional)")
	flags.StringVarP(&ga.patchedTag, "tag", "t", "", "Tag for the patched image")
	flags.StringVarP(&ga.suffix, "tag-suffix", "", "patched", "Suffix for the patched image (if no explicit --tag provided)")
	flags.StringVarP(&ga.workingFolder, "working-folder", "w", "", "Working folder, defaults to system temp folder")
	flags.StringVarP(&ga.bkOpts.Addr, "addr", "a", "", "Address of buildkitd service, defaults to local docker daemon with fallback to "+buildkit.DefaultAddr)
	flags.StringVarP(&ga.bkOpts.CACertPath, "cacert", "", "", "Absolute path to buildkitd CA certificate")
	flags.StringVarP(&ga.bkOpts.CertPath, "cert", "", "", "Absolute path to buildkit client certificate")
	flags.StringVarP(&ga.bkOpts.KeyPath, "key", "", "", "Absolute path to buildkit client key")
	flags.DurationVar(&ga.timeout, "timeout", 5*time.Minute, "Timeout for the operation, defaults to '5m'")
	flags.StringVarP(&ga.scanner, "scanner", "s", "trivy", "Scanner that generated the report, defaults to 'trivy'")
	flags.BoolVar(&ga.ignoreError, "ignore-errors", false, "Ignore errors during patching")
	flags.StringVarP(&ga.format, "format", "f", "openvex", "Output format, defaults to 'openvex'")
	flags.StringVarP(&ga.output, "output", "o", "", "Output file path")
	flags.StringSliceVar(&ga.platform, "platform", nil,
		"Target platform(s) for multi-arch images when no report directory is provided (e.g., linux/amd64,linux/arm64). "+
			"Valid platforms: linux/amd64, linux/arm64, linux/riscv64, linux/ppc64le, linux/s390x, linux/386, linux/arm/v7, linux/arm/v6. "+
			"If platform flag is used, only specified platforms are patched and the rest are preserved. If not specified, all platforms present in the image are patched.")
	flags.StringVarP(&ga.loader, "loader", "l", "", "Loader to use for loading images. Options: 'docker', 'podman', or empty for auto-detection based on buildkit address")
	flags.StringVar(&ga.outputContext, "output-context", "", "Path to save the generated tar context (instead of stdout)")
	flags.StringVar(&ga.progress, "progress", "auto", "Set the buildkit display mode (auto, plain, tty, quiet or rawjson). Set to quiet to discard all output.")

	// Experimental flags - only available when COPA_EXPERIMENTAL=1
	if os.Getenv("COPA_EXPERIMENTAL") == "1" {
		flags.StringVar(&ga.pkgTypes, "pkg-types", utils.PkgTypeOS,
			"[EXPERIMENTAL] Package types to patch, comma-separated list of 'os' and 'library'. "+
				"Defaults to 'os' for OS vulnerabilities only")
		flags.StringVar(&ga.libraryPatchLevel, "library-patch-level", utils.PatchTypePatch,
			"[EXPERIMENTAL] Library patch level preference: 'patch', 'minor', or 'major'. "+
				"Only applicable when 'library' is included in --pkg-types. Defaults to 'patch'")
	} else {
		// Set default values when experimental flags are not enabled
		ga.pkgTypes = utils.PkgTypeOS
		ga.libraryPatchLevel = utils.PatchTypePatch
	}

	if err := generateCmd.MarkFlagRequired("image"); err != nil {
		panic(err)
	}

	return generateCmd
}

// validateLibraryPatchLevel validates the library patch level flag and its usage.
func validateLibraryPatchLevel(libraryPatchLevel, pkgTypes string) error {
	// Valid library patch levels
	validLevels := map[string]bool{
		utils.PatchTypePatch: true,
		utils.PatchTypeMinor: true,
		utils.PatchTypeMajor: true,
	}

	// Check if the provided level is valid
	if !validLevels[libraryPatchLevel] {
		return fmt.Errorf("invalid library patch level '%s': must be one of 'patch', 'minor', or 'major'", libraryPatchLevel)
	}

	// If library patch level is specified and not the default, ensure library is in pkg-types
	if libraryPatchLevel != utils.PatchTypePatch && !strings.Contains(pkgTypes, utils.PkgTypeLibrary) {
		return fmt.Errorf("--library-patch-level can only be used when 'library' is included in --pkg-types")
	}

	return nil
}
