package patch

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/distribution/reference"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/types"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
)

// patchMultiPlatformImage patches a multi-platform image across all discovered platforms.
func patchMultiPlatformImage(
	ctx context.Context,
	ch chan error,
	opts *types.Options,
	discoveredPlatforms []types.PatchPlatform,
) error {
	image := opts.Image
	reportDir := opts.Report
	ignoreError := opts.IgnoreError
	log.Debugf("Handling platform specific errors with ignore-errors=%t", ignoreError)

	var platforms []types.PatchPlatform
	if reportDir != "" {
		// Using report directory - discover platforms from reports
		var err error
		platforms, err = buildkit.DiscoverPlatforms(image, reportDir, opts.Scanner)
		if err != nil {
			return err
		}
		if len(platforms) == 0 {
			return fmt.Errorf("no patchable platforms found for image %s", image)
		}
	} else {
		// No report directory - use discovered platforms and filter
		if len(discoveredPlatforms) == 0 {
			return fmt.Errorf("no platforms provided for image %s", image)
		}

		if len(opts.Platforms) > 0 {
			// Filter platforms based on user specification and validate
			patchPlatforms := filterPlatforms(discoveredPlatforms, opts.Platforms)
			if len(patchPlatforms) == 0 {
				return fmt.Errorf("none of the specified platforms %v are available in the image", opts.Platforms)
			}

			// Create a map to track which platforms should be patched
			shouldPatchMap := make(map[string]bool)
			for _, p := range patchPlatforms {
				key := buildkit.PlatformKey(p.Platform)
				shouldPatchMap[key] = true
			}

			// Process all platforms, marking which should be patched vs preserved
			for _, p := range discoveredPlatforms {
				platformCopy := p
				key := buildkit.PlatformKey(p.Platform)
				if shouldPatchMap[key] {
					// Platform should be patched
					platformCopy.ReportFile = ""
					platformCopy.ShouldPreserve = false
				} else {
					// Platform should be preserved
					platformCopy.ShouldPreserve = true
				}
				platforms = append(platforms, platformCopy)
			}

			log.Infof("Patching specified platforms, preserving others")
		} else {
			// Patch all available platforms since no specific platforms were requested
			for _, p := range discoveredPlatforms {
				platformCopy := p
				platformCopy.ReportFile = "" // No vulnerability report, just patch with latest packages
				platformCopy.ShouldPreserve = false
				platforms = append(platforms, platformCopy)
			}
			log.Infof("Patching all available platforms")
		}
	}

	sem := make(chan struct{}, runtime.NumCPU())
	g, gctx := errgroup.WithContext(ctx)

	var mu sync.Mutex
	patchResults := []types.PatchResult{}

	summaryMap := make(map[string]*types.MultiPlatformSummary)

	for _, p := range platforms {
		// rebind
		p := p //nolint
		platformKey := buildkit.PlatformKey(p.Platform)
		g.Go(func() error {
			select {
			case sem <- struct{}{}:
			case <-gctx.Done():
				return gctx.Err()
			}
			defer func() { <-sem }()

			if p.ShouldPreserve {
				// Platform marked for preservation - preserve original
				log.Infof("Platform %s marked for preservation, preserving original in manifest", p.OS+"/"+p.Architecture)

				// Parse the original image reference for the result
				originalRef, err := reference.ParseNormalizedNamed(image)
				if err != nil {
					mu.Lock()
					summaryMap[platformKey] = &types.MultiPlatformSummary{
						Platform: platformKey,
						Status:   "Error",
						Ref:      "",
						Message:  fmt.Sprintf("failed to parse original image reference: %v", err),
					}
					mu.Unlock()
					return err
				}

				// Handle Windows platform without push enabled
				if !opts.Push && p.OS == "windows" {
					mu.Lock()
					defer mu.Unlock()
					if !ignoreError {
						summaryMap[platformKey] = &types.MultiPlatformSummary{
							Platform: platformKey,
							Status:   "Error",
							Ref:      originalRef.String() + " (original reference)",
							Message:  "Windows images are not patched",
						}
						return errors.New("cannot save Windows platform image without pushing to registry. Use --push flag to save Windows images to a registry or run with --ignore-errors")
					}
					summaryMap[platformKey] = &types.MultiPlatformSummary{
						Platform: platformKey,
						Status:   "Ignored",
						Ref:      originalRef.String() + " (original reference)",
						Message:  "Windows images are not patched and will be preserved as-is",
					}
					log.Warn("Cannot save Windows platform image without pushing to registry. Use --push flag to save Windows images to a registry.")
					return nil
				}

				// Get the original platform descriptor from the manifest
				originalDesc, err := getPlatformDescriptorFromManifest(image, &p)
				if err != nil {
					mu.Lock()
					summaryMap[platformKey] = &types.MultiPlatformSummary{
						Platform: platformKey,
						Status:   "Error",
						Ref:      "",
						Message:  fmt.Sprintf("failed to get original descriptor for platform %s: %v", p.OS+"/"+p.Architecture, err),
					}
					mu.Unlock()
					return err
				}

				// For platforms without reports, use the original image digest/reference
				result := types.PatchResult{
					OriginalRef: originalRef,
					PatchedRef:  originalRef,
					PatchedDesc: originalDesc,
				}

				mu.Lock()
				patchResults = append(patchResults, result)
				// Add summary entry for unpatched platform
				summaryMap[platformKey] = &types.MultiPlatformSummary{
					Platform: platformKey,
					Status:   "Not Patched",
					Ref:      originalRef.String() + " (original reference)",
					Message:  "Preserved original image (No Scan Report provided for platform)",
				}
				mu.Unlock()
				return nil
			}

			// When no report directory is provided, patch with empty report file
			reportFile := p.ReportFile
			if reportDir == "" {
				reportFile = ""
			}

			patchOpts := *opts
			patchOpts.Report = reportFile
			res, err := patchSingleArchImage(gctx, ch, &patchOpts, p, true)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if errors.Is(err, types.ErrNoUpdatesFound) {
					patchResults = append(patchResults, *res)
					summaryMap[platformKey] = &types.MultiPlatformSummary{
						Platform: platformKey,
						Status:   "Up-to-date",
						Ref:      res.OriginalRef.String() + " (original)",
						Message:  "Image is already up-to-date",
					}
					return nil
				}

				status := "Error"
				if ignoreError {
					status = "Ignored"
				}
				summaryMap[platformKey] = &types.MultiPlatformSummary{
					Platform: platformKey,
					Status:   status,
					Ref:      "",
					Message:  err.Error(),
				}
				if !ignoreError {
					return err
				}
				return nil
			}
			if res == nil {
				summaryMap[platformKey] = &types.MultiPlatformSummary{
					Platform: platformKey,
					Status:   "Error",
					Ref:      "",
					Message:  "patchSingleArchImage returned nil result",
				}
				return nil
			}

			patchResults = append(patchResults, *res)
			summaryMap[platformKey] = &types.MultiPlatformSummary{
				Platform: platformKey,
				Status:   "Patched",
				Ref:      res.PatchedRef.String(),
				Message:  fmt.Sprintf("Successfully patched image (%s)", p.OS+"/"+p.Architecture),
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	// resolve image ref
	imageName, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return fmt.Errorf("failed to parse reference: %w", err)
	}

	resolvedImage, resolvedPatchedTag, err := common.ResolvePatchedImageName(imageName, opts.PatchedTag, opts.Suffix)
	if err != nil {
		return err
	}

	patchedImage, err := reference.ParseNormalizedNamed(resolvedImage)
	if err != nil {
		return fmt.Errorf("failed to parse reference: %w", err)
	}

	patchedImageName, err := reference.WithTag(patchedImage, resolvedPatchedTag)
	if err != nil {
		return fmt.Errorf("failed to parse patched image name: %w", err)
	}

	if opts.Push {
		err = createMultiPlatformManifest(ctx, patchedImageName, patchResults, image)
		if err != nil {
			return fmt.Errorf("manifest list creation failed: %w", err)
		}
	}

	if !opts.Push {
		// Show push commands only for actually patched images (not preserved originals)
		patchedOnlyResults := make([]types.PatchResult, 0)
		for _, result := range patchResults {
			// Only include results where the patched ref differs from original ref
			if result.PatchedRef.String() != result.OriginalRef.String() {
				patchedOnlyResults = append(patchedOnlyResults, result)
			}
		}

		if len(patchedOnlyResults) > 0 {
			log.Info("To push the individual architecture images, run:")
			for _, result := range patchedOnlyResults {
				log.Infof("  docker push %s", result.PatchedRef.String())
			}
			log.Infof("To create and push the multi-platform manifest, run:")

			// Include all platforms (both patched and preserved) in the manifest create command
			refs := make([]string, len(patchResults))
			for i, result := range patchResults {
				if result.PatchedRef.String() != result.OriginalRef.String() {
					// Use the patched reference for actually patched platforms
					refs[i] = result.PatchedRef.String()
				} else {
					// Use the original reference with digest for preserved platforms
					if result.PatchedDesc != nil && result.PatchedDesc.Digest.String() != "" {
						refs[i] = result.OriginalRef.String() + "@" + result.PatchedDesc.Digest.String()
					} else {
						refs[i] = result.OriginalRef.String()
					}
				}
			}

			log.Infof("  docker buildx imagetools create --tag %s %s", patchedImageName.String(), strings.Join(refs, " "))
		} else {
			return fmt.Errorf("no images were processed, check the logs for errors")
		}
	}

	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PLATFORM\tSTATUS\tREFERENCE\tMESSAGE")

	for _, p := range platforms {
		platformKey := buildkit.PlatformKey(p.Platform)
		s := summaryMap[platformKey]
		if s != nil {
			ref := s.Ref
			if ref == "" {
				ref = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Platform, s.Status, ref, s.Message)
		}
	}
	w.Flush()
	log.Info("\nMulti-arch patch summary:\n" + b.String())

	anyPatchesApplied := false
	for _, summary := range summaryMap {
		if summary.Status == "Patched" {
			anyPatchesApplied = true
			break
		}
	}
	if !anyPatchesApplied && len(summaryMap) > 0 {
		return types.ErrNoUpdatesFound
	}

	return nil
}
