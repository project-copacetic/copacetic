package main

import (
	"os"
	"strings"

	"github.com/project-copacetic/copacetic/pkg/generate"
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
	rootCmd.AddCommand(generate.NewGenerateCmd())
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
		os.Exit(1)
	}
}
