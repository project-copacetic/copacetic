package testprovenance

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/project-copacetic/copacetic/pkg/provenance"
	"github.com/spf13/cobra"
)

func NewTestProvenanceCmd() *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
		Use:   "test-provenance <image>",
		Short: "Test SLSA provenance fetching and parsing (development only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			imageRef := args[0]

			fmt.Printf("Testing SLSA provenance for: %s\n", imageRef)
			fmt.Println(strings.Repeat("=", 70))

			ctx := context.Background()

			// Fetch attestation
			fetcher := provenance.NewFetcher()
			attestation, err := fetcher.FetchAttestation(ctx, imageRef)
			if err != nil {
				fmt.Printf("❌ Failed to fetch provenance: %v\n", err)
				return err
			}

			fmt.Printf("✅ Successfully fetched SLSA provenance!\n")
			fmt.Printf("   Type: %s\n", attestation.PredicateType)
			fmt.Printf("   Level: %d\n", attestation.SLSALevel)
			fmt.Println()

			// Parse build info
			parser := provenance.NewParser()
			buildInfo, err := parser.ParseBuildInfo(attestation)
			if err != nil {
				fmt.Printf("⚠️  Failed to parse build info: %v\n", err)
				return err
			}

			fmt.Println("📋 Build Information:")
			fmt.Println(strings.Repeat("=", 70))
			fmt.Printf("Go Version:      %s\n", buildInfo.GoVersion)
			fmt.Printf("Base Image:      %s\n", buildInfo.BaseImage)
			fmt.Printf("Builder ID:      %s\n", buildInfo.BuilderID)
			fmt.Printf("CGO Enabled:     %v\n", buildInfo.CGOEnabled)
			fmt.Printf("Main Package:    %s\n", buildInfo.MainPackage)
			fmt.Printf("Module Path:     %s\n", buildInfo.ModulePath)
			fmt.Printf("Provenance Mode: %s\n", buildInfo.ProvenanceMode)
			fmt.Printf("Build Command:   %s\n", buildInfo.BuildCommand)
			fmt.Printf("Build Flags:     %v\n", buildInfo.BuildFlags)
			fmt.Printf("Workdir:         %s\n", buildInfo.Workdir)

			if buildInfo.Dockerfile != "" {
				fmt.Printf("\n📄 Dockerfile Found: %d bytes\n", len(buildInfo.Dockerfile))
				previewLen := min(200, len(buildInfo.Dockerfile))
				fmt.Println("   (First 200 chars):", buildInfo.Dockerfile[:previewLen])
			}

			fmt.Println()

			// Assess completeness
			completeness := parser.AssessCompleteness(buildInfo)
			fmt.Println("🔍 Completeness Assessment:")
			fmt.Println(strings.Repeat("=", 70))
			fmt.Printf("Has Dockerfile:    %v\n", completeness.HasDockerfile)
			fmt.Printf("Has Build Command: %v\n", completeness.HasBuildCommand)
			fmt.Printf("Has Base Image:    %v\n", completeness.HasBaseImage)
			fmt.Printf("Has Go Version:    %v\n", completeness.HasGoVersion)
			fmt.Printf("Can Rebuild:       %v\n", completeness.CanRebuild)

			if len(completeness.MissingInfo) > 0 {
				fmt.Printf("\n⚠️  Missing Info: %v\n", completeness.MissingInfo)
			}

			fmt.Println()

			// Show raw predicate (sample)
			if verbose {
				fmt.Println("📦 Raw Predicate (JSON):")
				fmt.Println(strings.Repeat("=", 70))
				predicateJSON, _ := json.MarshalIndent(attestation.Predicate, "", "  ")
				fmt.Println(string(predicateJSON))
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show raw provenance JSON")

	return cmd
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
