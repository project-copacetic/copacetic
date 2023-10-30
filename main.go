/*
Copyright (c) Project Copacetic authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if debug {
				log.SetLevel(log.DebugLevel)
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
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
		os.Exit(1)
	}
}
