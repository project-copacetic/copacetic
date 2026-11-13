package patch

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/ocilayout"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/vex"
)

// validateOCIVEXDestination rejects a VEX format or destination that the VEX
// writer would refuse. With OCI layout input, VEX is written only after the
// output layout is published, so failing then would leave a published layout
// without its VEX document. The writer follows links, including a final link
// whose target does not exist yet, so the check applies to the file the write
// reaches: an existing regular file, or a new file in an existing directory.
func validateOCIVEXDestination(path, format string) error {
	if err := vex.ValidateFormat(format); err != nil {
		return err
	}
	target, err := ocilayout.ResolveWritePath(path)
	if err != nil {
		// Includes a parent that is not a directory (ENOTDIR).
		return fmt.Errorf("resolve VEX output %q: %w", path, err)
	}
	info, err := os.Stat(target)
	if err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("VEX output %q exists and is not a regular file", path)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("stat VEX output %q: %w", path, err)
	}
	parent := filepath.Dir(target)
	if _, err := os.Stat(parent); err != nil {
		return fmt.Errorf("VEX output %q: parent directory %q: %w", path, parent, err)
	}
	return nil
}

// writeOCIVEX binds only validated patches to manifests in the final output.
// Using each platform manifest avoids claiming remediation for preserved peers.
// Products follow the order of results.
func writeOCIVEX(ctx context.Context, opts *types.Options, results []types.PatchResult, outputReference string) error {
	if opts.OCISource == nil || opts.Output == "" {
		return nil
	}
	var eligible []types.PatchResult
	for _, result := range results {
		if result.VEX == nil || result.VEX.Updates == nil ||
			(len(result.VEX.Updates.OSUpdates) == 0 && len(result.VEX.Updates.LangUpdates) == 0) {
			continue
		}
		eligible = append(eligible, result)
	}
	// Reading the output validates every exported blob, so skip it when no
	// result has a validated update to report.
	if len(eligible) == 0 {
		return nil
	}
	output, err := ocilayout.Open(ctx, opts.OCIDir, "", "")
	if err != nil {
		return fmt.Errorf("read final OCI output for VEX: %w", err)
	}
	// The output did not exist when Patch first validated the VEX path, so an
	// alias of it, such as a case variant on a case-insensitive filesystem,
	// could only be compared by text then. Check again by identity now that
	// the output exists, before writing anything into it.
	if err := ocilayout.ValidateOutputWritePath(output.Path, opts.Output); err != nil {
		return err
	}
	images := make([]vex.ImageUpdates, 0, len(eligible))
	for _, result := range eligible {
		if result.PatchedDesc == nil || result.PatchedDesc.Platform == nil {
			return fmt.Errorf("OCI VEX result is missing its validated platform")
		}
		desc, err := output.PlatformDescriptor(ctx, result.PatchedDesc.Platform)
		if err != nil {
			return fmt.Errorf("resolve final OCI platform for VEX: %w", err)
		}
		images = append(images, vex.ImageUpdates{
			Updates:          result.VEX.Updates,
			PkgType:          result.VEX.PkgType,
			PatchedImageName: common.GetRepoNameWithDigest(outputReference, desc.Digest.String()),
		})
	}
	return vex.TryOutputMultiVexDocument(images, opts.Format, opts.Output)
}

// resultsInPlatformOrder returns results sorted by the order of platforms, so
// VEX products follow platforms as they do for registry and daemon images.
// Results without a known platform sort last in their original order.
func resultsInPlatformOrder(platforms []types.PatchPlatform, results []types.PatchResult) []types.PatchResult {
	rank := make(map[string]int, len(platforms))
	for i, p := range platforms {
		if _, ok := rank[buildkit.PlatformKey(p.Platform)]; !ok {
			rank[buildkit.PlatformKey(p.Platform)] = i
		}
	}
	position := func(result *types.PatchResult) int {
		if result.PatchedDesc == nil || result.PatchedDesc.Platform == nil {
			return len(platforms)
		}
		if i, ok := rank[buildkit.PlatformKey(*result.PatchedDesc.Platform)]; ok {
			return i
		}
		return len(platforms)
	}
	ordered := slices.Clone(results)
	slices.SortStableFunc(ordered, func(a, b types.PatchResult) int {
		return cmp.Compare(position(&a), position(&b))
	})
	return ordered
}
