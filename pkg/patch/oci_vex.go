package patch

import (
	"context"
	"fmt"

	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/ocilayout"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/vex"
)

// writeOCIVEX binds only validated patches to manifests in the final output.
// Using each platform manifest avoids claiming remediation for preserved peers.
func writeOCIVEX(ctx context.Context, opts *types.Options, results []types.PatchResult, outputReference string) error {
	if opts.OCISource == nil || opts.Output == "" {
		return nil
	}
	var inputs []vex.DocumentInput
	output, err := ocilayout.Open(ctx, opts.OCIDir, "", "")
	if err != nil {
		return fmt.Errorf("read final OCI output for VEX: %w", err)
	}
	for _, result := range results {
		if result.VEX == nil || result.VEX.Updates == nil ||
			(len(result.VEX.Updates.OSUpdates) == 0 && len(result.VEX.Updates.LangUpdates) == 0) {
			continue
		}
		if result.PatchedDesc == nil || result.PatchedDesc.Platform == nil {
			return fmt.Errorf("OCI VEX result is missing its validated platform")
		}
		desc, err := output.PlatformDescriptor(ctx, result.PatchedDesc.Platform)
		if err != nil {
			return fmt.Errorf("resolve final OCI platform for VEX: %w", err)
		}
		inputs = append(inputs, vex.DocumentInput{
			Updates:     result.VEX.Updates,
			PackageType: result.VEX.PackageType,
			Image:       common.GetRepoNameWithDigest(outputReference, desc.Digest.String()),
		})
	}
	if len(inputs) == 0 {
		return nil
	}
	return vex.TryOutputVexDocuments(inputs, opts.Format, opts.Output)
}
