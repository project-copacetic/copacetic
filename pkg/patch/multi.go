package patch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/distribution/reference"
	"github.com/moby/buildkit/client"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/tui"
	"github.com/project-copacetic/copacetic/pkg/types"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var resolveImageSource = buildkit.ResolveImageSource

// patchMultiPlatformImage patches a multi-platform image across all discovered platforms.
func patchMultiPlatformImage(
	ctx context.Context,
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

	source, err := captureMultiPlatformSource(ctx, image)
	if err != nil {
		log.Warnf("Unable to capture multi-platform source lineage for %s; lineage annotations will be omitted where identity is unknown: %v", image, err)
		source = nil
	}

	// Display styled patching plan before starting
	plan := buildPatchingPlan(opts, platforms)
	fmt.Fprintln(os.Stderr, tui.RenderPatchingPlan(plan))

	// Create a shared progress channel for unified TUI display.
	// Buffered to prevent backpressure from the display blocking BuildKit.
	sharedProgressCh := make(chan *client.SolveStatus, 128)

	// Count how many platforms will be patched (not preserved) to know when to close the channel
	var patchingPlatformCount int32
	for _, p := range platforms {
		if !p.ShouldPreserve {
			patchingPlatformCount++
		}
	}
	var completedCount atomic.Int32
	var closeProgressOnce sync.Once

	sem := make(chan struct{}, runtime.NumCPU())
	g, gctx := errgroup.WithContext(ctx)

	// Start the unified progress display
	displayEg, displayCtx := errgroup.WithContext(ctx)
	common.DisplayProgress(displayCtx, displayEg, sharedProgressCh, opts.Progress)
	if patchingPlatformCount == 0 {
		closeProgressOnce.Do(func() { close(sharedProgressCh) })
	}

	var mu sync.Mutex
	patchResults := []types.PatchResult{}

	summaryMap := make(map[string]*types.MultiPlatformSummary)

	// Track if any platforms errored, and patch attempt/success stats (exclude preserved)
	var hasErrors bool
	var patchedAttempts int
	var patchedSuccesses int

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
				log.Debugf("Platform %s marked for preservation, preserving original in manifest", p.OS+"/"+p.Architecture)

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
					hasErrors = true
					mu.Unlock()
					// Continue processing other platforms
					return nil
				}

				// Handle Windows platform without push enabled
				if !opts.Push && p.OS == "windows" {
					mu.Lock()
					defer mu.Unlock()
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
				var originalDesc *ispec.Descriptor
				if source != nil && source.Current != nil {
					originalDesc, err = source.Current.PlatformDescriptor(&p.Platform)
				} else {
					originalDesc, err = getPlatformDescriptorFromManifest(image, &p)
				}
				if err != nil {
					mu.Lock()
					summaryMap[platformKey] = &types.MultiPlatformSummary{
						Platform: platformKey,
						Status:   "Error",
						Ref:      "",
						Message:  fmt.Sprintf("failed to get original descriptor for platform %s: %v", p.OS+"/"+p.Architecture, err),
					}
					hasErrors = true
					mu.Unlock()
					// Continue processing other platforms
					return nil
				}

				// For platforms without reports, use the original image digest/reference
				result := types.PatchResult{
					OriginalRef: originalRef,
					PatchedRef:  originalRef,
					PatchedDesc: originalDesc,
				}

				mu.Lock()
				patchResults = append(patchResults, result)
				var preserveReason string
				if reportDir != "" && p.ReportFile == "" {
					preserveReason = "No scan report for platform"
				} else {
					preserveReason = "Not in --platform list"
				}
				// Add summary entry for unpatched platform
				summaryMap[platformKey] = &types.MultiPlatformSummary{
					Platform: platformKey,
					Status:   "Not Patched",
					Ref:      originalRef.String() + " (original reference)",
					Message:  preserveReason,
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

			// Count a real patch attempt (not preserved)
			mu.Lock()
			patchedAttempts++
			mu.Unlock()

			var sourceImage string
			if source != nil && source.Current != nil {
				var sourceErr error
				sourceImage, sourceErr = platformSourceReference(source.Current, &p.Platform)
				if sourceErr != nil {
					log.Warnf("Unable to pin source platform %s for lineage: %v", platformKey, sourceErr)
				}
			}

			res, err := patchSingleArchImageWithSource(gctx, &patchOpts, p, true, sharedProgressCh, sourceImage)

			// Track completion to know when to close shared channel
			if completedCount.Add(1) == patchingPlatformCount {
				closeProgressOnce.Do(func() { close(sharedProgressCh) })
			}

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if errors.Is(err, types.ErrNoUpdatesFound) {
					patchResults = append(patchResults, *res)
					markPlatformPreserved(platforms, platformKey)
					summaryMap[platformKey] = &types.MultiPlatformSummary{
						Platform: platformKey,
						Status:   "Up-to-date",
						Ref:      res.OriginalRef.String() + " (original)",
						Message:  "Already up-to-date",
					}
					patchedSuccesses++ // Count up-to-date as success
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
				hasErrors = true
				// Continue processing other platforms
				return nil
			}
			if res == nil {
				summaryMap[platformKey] = &types.MultiPlatformSummary{
					Platform: platformKey,
					Status:   "Error",
					Ref:      "",
					Message:  "patchSingleArchImage returned nil result",
				}
				hasErrors = true
				return nil
			}

			patchResults = append(patchResults, *res)
			summaryMap[platformKey] = &types.MultiPlatformSummary{
				Platform: platformKey,
				Status:   "Patched",
				Ref:      res.PatchedRef.String(),
				Message:  "Successfully patched",
			}
			patchedSuccesses++
			return nil
		})
	}

	// Wait for all goroutines to complete (don't fail early on errors if ignoring errors)
	if err := g.Wait(); err != nil && !ignoreError {
		// g.Wait() will return the first non-nil error from any goroutine
		// But since we're now returning nil from all goroutines, this should only
		// happen if context is canceled
		// Ensure the progress channel is closed on early exit
		closeProgressOnce.Do(func() { close(sharedProgressCh) })
		_ = displayEg.Wait()
		return err
	}

	// Wait for the progress display to finish
	_ = displayEg.Wait()

	// Render the per-platform summary before any early error returns so users
	// can see which platforms failed and why.
	var summaries []tui.PlatformSummary
	for _, p := range platforms {
		platformKey := buildkit.PlatformKey(p.Platform)
		s := summaryMap[platformKey]
		if s != nil {
			ref := s.Ref
			if ref == "" {
				ref = "-"
			}
			summaries = append(summaries, tui.PlatformSummary{
				Platform: s.Platform,
				Status:   s.Status,
				Ref:      ref,
				Message:  s.Message,
			})
		}
	}
	fmt.Fprintln(os.Stderr, tui.RenderPatchSummary(summaries))

	// With strict error handling, fail if any platform encountered an error.
	if hasErrors && !ignoreError {
		return fmt.Errorf("one or more platform patches failed")
	}

	// When ignoring errors, still fail if every real patch attempt failed.
	// Only consider real patch attempts (exclude preserved).
	if hasErrors && patchedAttempts > 0 && patchedSuccesses == 0 {
		return fmt.Errorf("all platform patches failed")
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

	var originalIndexAnnotations map[string]string
	if source != nil && source.Current != nil && source.Current.Index != nil {
		originalIndexAnnotations = source.Current.Index.Annotations
	}
	indexLineage := commonBaseIndexLineage(source, patchResults)

	if opts.Push {
		err = createMultiPlatformManifest(ctx, patchedImageName, patchResults, originalIndexAnnotations, indexLineage)
		if err != nil {
			return fmt.Errorf("manifest list creation failed: %w", err)
		}
	}

	if !opts.Push {
		// Show push commands only for actually patched images (not preserved originals)
		log.Debugf("Total patch results: %d", len(patchResults))
		patchedOnlyResults := make([]types.PatchResult, 0)
		for _, result := range patchResults {
			// Only include results where the patched ref differs from original ref
			log.Debugf("Checking result: PatchedRef=%s, OriginalRef=%s", result.PatchedRef.String(), result.OriginalRef.String())
			if result.PatchedRef.String() != result.OriginalRef.String() {
				patchedOnlyResults = append(patchedOnlyResults, result)
			}
		}

		if len(patchedOnlyResults) > 0 {
			// Build push commands
			pushCommands := make([]string, len(patchedOnlyResults))
			for i, result := range patchedOnlyResults {
				pushCommands[i] = fmt.Sprintf("docker push %s", result.PatchedRef.String())
			}

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

			manifestCmd := fmt.Sprintf("docker buildx imagetools create --tag %s %s", patchedImageName.String(), strings.Join(refs, " "))

			// Render styled next steps
			nextSteps := tui.NextSteps{
				SuccessMessage:  "Image loaded successfully",
				PushCommands:    pushCommands,
				ManifestCommand: manifestCmd,
			}
			fmt.Fprintln(os.Stderr, tui.RenderNextSteps(nextSteps))
		}
		// If no patches were needed (all up-to-date), that's fine - don't return an error
	}

	anySuccesses := false
	for _, summary := range summaryMap {
		if summary.Status == "Patched" || summary.Status == "Up-to-date" {
			anySuccesses = true
			break
		}
	}
	if !anySuccesses && len(summaryMap) > 0 {
		return types.ErrNoUpdatesFound
	}
	// Create OCI layout if requested and not pushing to registry
	if opts.OCIDir != "" && !opts.Push {
		compression := opts.Compression
		if compression == "" {
			compression = DefaultLocalExportCompression
		}
		preservedSourceRef, err := immutableCurrentIndexReference(source)
		if err != nil {
			return fmt.Errorf("failed to identify immutable source for preserved platforms: %w", err)
		}
		if err := buildkit.CreateOCILayoutFromResultsWithOptions(
			opts.OCIDir,
			patchResults,
			platforms,
			buildkit.OCILayoutExportOptions{
				Compression:        compression,
				ForceCompression:   opts.ForceCompression,
				IndexAnnotations:   multiPlatformIndexAnnotations(patchedImageName, originalIndexAnnotations, indexLineage, time.Now().UTC()),
				PreservedSourceRef: preservedSourceRef,
			},
		); err != nil {
			log.Warnf("Failed to create OCI layout: %v", err)
			return fmt.Errorf("failed to create OCI layout: %w", err)
		}
	}

	return nil
}

type multiPlatformSource struct {
	Current      *buildkit.ImageSource
	Base         *buildkit.ImageSource
	IndexLineage *types.SourceLineage
}

func captureMultiPlatformSource(ctx context.Context, image string) (*multiPlatformSource, error) {
	current, err := resolveImageSource(ctx, image)
	if err != nil {
		return nil, err
	}
	if current.Index == nil {
		return nil, fmt.Errorf("source %s is not an image index", current.Name)
	}

	source := &multiPlatformSource{Current: current}
	if _, repatch := current.Index.Annotations[copaAnnotationKeyPrefix+".patched"]; !repatch {
		source.Base = current
		source.IndexLineage = &types.SourceLineage{Name: current.Name, Digest: current.Descriptor.Digest}
		return source, nil
	}

	recorded := sourceLineageFromAnnotations(current.Index.Annotations)
	if !recorded.Valid() {
		return source, nil
	}
	pinned, err := immutableLineageReference(recorded)
	if err != nil {
		return source, nil
	}
	base, err := resolveImageSource(ctx, pinned)
	if err != nil || base.Index == nil || base.Descriptor.Digest != recorded.Digest {
		return source, nil
	}
	source.Base = base
	source.IndexLineage = recorded
	return source, nil
}

func sourceLineageFromAnnotations(annotations map[string]string) *types.SourceLineage {
	lineageDigest, err := digest.Parse(annotations[ispec.AnnotationBaseImageDigest])
	if err != nil {
		return nil
	}
	lineageName, err := reference.ParseNormalizedNamed(annotations[ispec.AnnotationBaseImageName])
	if err != nil {
		return nil
	}
	if reference.IsNameOnly(lineageName) {
		lineageName = reference.TagNameOnly(lineageName)
	}
	return &types.SourceLineage{Name: lineageName.String(), Digest: lineageDigest}
}

func immutableLineageReference(lineage *types.SourceLineage) (string, error) {
	if !lineage.Valid() {
		return "", errors.New("source lineage is incomplete")
	}
	name, err := reference.ParseNormalizedNamed(lineage.Name)
	if err != nil {
		return "", err
	}
	pinned, err := reference.WithDigest(reference.TrimNamed(name), lineage.Digest)
	if err != nil {
		return "", err
	}
	return pinned.String(), nil
}

func immutableCurrentIndexReference(source *multiPlatformSource) (reference.Canonical, error) {
	if source == nil || source.Current == nil {
		return nil, nil
	}
	if err := source.Current.Descriptor.Digest.Validate(); err != nil {
		return nil, fmt.Errorf("current index digest is invalid: %w", err)
	}
	name, err := reference.ParseNormalizedNamed(source.Current.Name)
	if err != nil {
		return nil, err
	}
	pinned, err := reference.WithDigest(reference.TrimNamed(name), source.Current.Descriptor.Digest)
	if err != nil {
		return nil, err
	}
	return pinned, nil
}

func platformSourceReference(source *buildkit.ImageSource, platform *ispec.Platform) (string, error) {
	if source == nil {
		return "", errors.New("source is nil")
	}
	descriptor, err := source.PlatformDescriptor(platform)
	if err != nil {
		return "", err
	}
	name, err := reference.ParseNormalizedNamed(source.Name)
	if err != nil {
		return "", err
	}
	pinned, err := reference.WithDigest(reference.TrimNamed(name), descriptor.Digest)
	if err != nil {
		return "", err
	}
	return pinned.String(), nil
}

func commonBaseIndexLineage(source *multiPlatformSource, items []types.PatchResult) *types.SourceLineage {
	if source == nil || source.Base == nil || !source.IndexLineage.Valid() || len(items) == 0 {
		log.Debug("Omitting index source lineage: source index identity is incomplete")
		return nil
	}
	for i := range items {
		item := &items[i]
		if item.PatchedDesc == nil || item.PatchedDesc.Platform == nil {
			log.Debug("Omitting index source lineage: result descriptor platform is unavailable")
			return nil
		}
		expected, err := source.Base.PlatformDescriptor(item.PatchedDesc.Platform)
		if err != nil {
			log.Debugf("Omitting index source lineage: source descriptor for platform %s is unavailable: %v", buildkit.PlatformKey(*item.PatchedDesc.Platform), err)
			return nil
		}

		patched := item.PatchedRef != nil && item.OriginalRef != nil && item.PatchedRef.String() != item.OriginalRef.String()
		if patched {
			if !item.SourceLineage.Valid() ||
				item.SourceLineage.Name != source.IndexLineage.Name ||
				item.SourceLineage.Digest != expected.Digest {
				log.Debugf("Omitting index source lineage: patched platform %s does not map to source descriptor %s", buildkit.PlatformKey(*item.PatchedDesc.Platform), expected.Digest)
				return nil
			}
			continue
		}
		if item.PatchedDesc.Digest == expected.Digest {
			continue
		}
		preservedLineage := sourceLineageFromAnnotations(item.PatchedDesc.Annotations)
		if !preservedLineage.Valid() ||
			preservedLineage.Name != source.IndexLineage.Name ||
			preservedLineage.Digest != expected.Digest {
			log.Debugf("Omitting index source lineage: preserved platform %s does not map to source descriptor %s", buildkit.PlatformKey(*item.PatchedDesc.Platform), expected.Digest)
			return nil
		}
	}
	lineage := *source.IndexLineage
	return &lineage
}

func markPlatformPreserved(platforms []types.PatchPlatform, targetKey string) {
	for i := range platforms {
		if buildkit.PlatformKey(platforms[i].Platform) == targetKey {
			platforms[i].ShouldPreserve = true
			return
		}
	}
}

// buildPatchingPlan creates a PatchingPlan from the options and platforms.
func buildPatchingPlan(opts *types.Options, platforms []types.PatchPlatform) tui.PatchingPlan {
	var targetPlatforms []string
	var preservedPlatforms []string

	for _, p := range platforms {
		platformStr := p.String() // Includes variant for ARM platforms
		if p.ShouldPreserve {
			preservedPlatforms = append(preservedPlatforms, platformStr)
		} else {
			targetPlatforms = append(targetPlatforms, platformStr)
		}
	}

	targetStr := strings.Join(targetPlatforms, ", ")
	if len(targetPlatforms) == 0 {
		targetStr = "all platforms"
	}

	// Use the same resolution logic as the actual patching to get accurate name
	patchedName := opts.Image + "-patched" // fallback
	if ref, err := reference.ParseNormalizedNamed(opts.Image); err == nil {
		if imageName, tag, err := common.ResolvePatchedImageName(ref, opts.PatchedTag, opts.Suffix); err == nil {
			patchedName = fmt.Sprintf("%s:%s", imageName, tag)
		}
	}

	return tui.PatchingPlan{
		TargetPlatform:     targetStr,
		PatchedImageName:   patchedName,
		PreservedPlatforms: preservedPlatforms,
	}
}
