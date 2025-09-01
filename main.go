package main

import (
	"os"
	"strings"

	"github.com/project-copacetic/copacetic/pkg/patch"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Globals for Debug logging flag and version reporting.
var (
	debug   bool
	version string
)

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "copa",
		Short: "Copacetic",
		Long:  "Project Copacetic: container patching tool",
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			if debug {
				log.SetLevel(log.DebugLevel)
			}
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Usage()
		},
		SilenceUsage: true,
		Version:      version,
	}

	flags := rootCmd.PersistentFlags()
	flags.BoolVar(&debug, "debug", false, "enable debug level logging")

	rootCmd.AddCommand(patch.NewPatchCmd())
	return rootCmd
}

func initConfig() {
	viper.SetEnvPrefix("copa")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}

func main() {
	cobra.OnInitialize(initConfig)
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "mergeop") || strings.Contains(errStr, "diffop") {
			log.Error(`
❌ Copa failed due to missing BuildKit features.

The requested BuildKit operations "mergeop" or "diffop" are disabled because your Docker or BuildKit setup is not using the containerd image store.

💡 To fix this:
- If you're using Docker Desktop:
  1. Open Docker Desktop.
  2. Go to ⚙️  Settings → Features in Development.
  3. Enable "Use containerd for storing and managing images".
  4. Restart Docker Desktop and try again.

- If you're using Docker CLI or Linux:
  - Ensure Docker is configured to use containerd as the image store.
  - Alternatively, run BuildKit standalone with a containerd backend.

🔗 More info: https://docs.docker.com/engine/storage/containerd/
			`)
		} else {
			log.Errorf("Error: %v", err)
		}
		os.Exit(1)
	}
}
