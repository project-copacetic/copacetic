package testprovenance

import (
	"fmt"
	"strings"

	"github.com/project-copacetic/copacetic/pkg/provenance"
	"github.com/spf13/cobra"
)

func NewDetectBinaryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detect-binary <binary-path>",
		Short: "Detect Go build information from a binary (development only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			binaryPath := args[0]

			fmt.Printf("Detecting build information from: %s\n", binaryPath)
			fmt.Println(strings.Repeat("=", 70))

			detector := provenance.NewDetector()

			// Check if it's a Go binary
			if !detector.IsGoBinary(binaryPath) {
				fmt.Printf("❌ %s is not a Go binary\n", binaryPath)
				return fmt.Errorf("not a Go binary")
			}

			fmt.Printf("✅ Confirmed Go binary\n\n")

			// Detect build info
			binaryInfo, err := detector.DetectBinaryInfo(binaryPath)
			if err != nil {
				fmt.Printf("❌ Failed to detect build info: %v\n", err)
				return err
			}

			// Display information
			fmt.Println("📋 Binary Information:")
			fmt.Println(strings.Repeat("=", 70))
			fmt.Printf("Path:           %s\n", binaryInfo.Path)
			fmt.Printf("Module Path:    %s\n", binaryInfo.ModulePath)
			fmt.Printf("Go Version:     %s\n", binaryInfo.GoVersion)
			fmt.Printf("GOOS:           %s\n", binaryInfo.GOOS)
			fmt.Printf("GOARCH:         %s\n", binaryInfo.GOARCH)
			fmt.Printf("CGO Enabled:    %v\n", binaryInfo.CGOEnabled)

			if binaryInfo.MainModule != "" {
				fmt.Printf("Main Module:    %s@%s\n", binaryInfo.MainModule, binaryInfo.MainModuleVersion)
			}

			if binaryInfo.VCS != "" {
				fmt.Printf("\nVCS Info:\n")
				fmt.Printf("  Type:         %s\n", binaryInfo.VCS)
				fmt.Printf("  Revision:     %s\n", binaryInfo.VCSRevision)
				if binaryInfo.VCSTime != "" {
					fmt.Printf("  Time:         %s\n", binaryInfo.VCSTime)
				}
				fmt.Printf("  Modified:     %v\n", binaryInfo.VCSModified)
			}

			fmt.Printf("\n📦 Dependencies (%d):\n", len(binaryInfo.Dependencies))
			fmt.Println(strings.Repeat("=", 70))
			if len(binaryInfo.Dependencies) > 0 {
				// Show first 10 dependencies
				count := 0
				for module, version := range binaryInfo.Dependencies {
					if count >= 10 {
						fmt.Printf("... and %d more\n", len(binaryInfo.Dependencies)-10)
						break
					}
					fmt.Printf("  %s@%s\n", module, version)
					count++
				}
			} else {
				fmt.Println("  (no dependencies)")
			}

			fmt.Printf("\n🔧 Build Settings:\n")
			fmt.Println(strings.Repeat("=", 70))
			if len(binaryInfo.BuildSettings) > 0 {
				for key, value := range binaryInfo.BuildSettings {
					fmt.Printf("  %s=%s\n", key, value)
				}
			} else {
				fmt.Println("  (no build settings)")
			}

			// Convert to BuildInfo for consistency check
			fmt.Printf("\n🔄 Conversion to BuildInfo:\n")
			fmt.Println(strings.Repeat("=", 70))
			buildInfo := detector.ConvertBinaryInfoToBuildInfo(binaryInfo)
			fmt.Printf("Go Version:     %s\n", buildInfo.GoVersion)
			fmt.Printf("Module Path:    %s\n", buildInfo.ModulePath)
			fmt.Printf("CGO Enabled:    %v\n", buildInfo.CGOEnabled)
			fmt.Printf("Dependencies:   %d\n", len(buildInfo.Dependencies))
			fmt.Printf("Build Args:     %d\n", len(buildInfo.BuildArgs))

			return nil
		},
	}

	return cmd
}
