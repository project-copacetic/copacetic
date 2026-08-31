package patch

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	buildkitclient "github.com/moby/buildkit/client"
	"github.com/moby/buildkit/util/progress/progressui"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/ocilayout"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/tui"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

// for testing.
var (
	bkNewClient = buildkit.NewClient
	listWorkers = func(ctx context.Context, client *buildkitclient.Client) ([]*buildkitclient.WorkerInfo, error) {
		return client.ListWorkers(ctx)
	}
)

// Patch command applies package updates to an OCI image given a vulnerability report for a given set of options.
func Patch(ctx context.Context, opts *types.Options) error {
	allowedProgressModes := map[string]struct{}{
		"auto":    {},
		"plain":   {},
		"tty":     {},
		"quiet":   {},
		"rawjson": {},
	}
	if _, ok := allowedProgressModes[string(opts.Progress)]; !ok {
		log.Warnf("Invalid value for --progress: %q. Allowed values are 'auto', 'plain' 'tty', 'quiet' or 'rawjson'. Defaulting to 'auto'.", string(opts.Progress))
		opts.Progress = progressui.DisplayMode("auto")
	}
	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	ch := make(chan error, 1)

	go func() {
		ch <- patchWithContext(timeoutCtx, opts)
		close(ch)
	}()
	select {
	case err := <-ch:
		if err != nil {
			// Display styled error
			fmt.Fprintln(os.Stderr, tui.RenderError(getErrorInfo(err)))
		}
		return err
	case <-timeoutCtx.Done():
		<-time.After(1 * time.Second)

		// Check if this was a cancellation (Ctrl+C) or actual timeout
		if ctx.Err() == context.Canceled {
			// Parent context was canceled (user pressed Ctrl+C)
			fmt.Fprintln(os.Stderr, tui.RenderError(tui.ErrorInfo{
				Title:   "Operation Canceled",
				Message: "Patch was canceled by user",
				Hint:    "",
			}))
			return context.Canceled
		}

		// Actual timeout
		err := fmt.Errorf("patch exceeded timeout %v", opts.Timeout)
		fmt.Fprintln(os.Stderr, tui.RenderError(tui.ErrorInfo{
			Title:   "Operation Timed Out",
			Message: fmt.Sprintf("Patch exceeded timeout of %v", opts.Timeout),
			Hint:    "Try increasing timeout with --timeout flag (e.g., --timeout 10m)",
		}))
		return err
	}
}

// patchWithContext orchestrates the main patching workflow.
func patchWithContext(ctx context.Context, opts *types.Options) error {
	// Configure EOL API if provided
	if opts.EOLAPIBaseURL != "" {
		utils.SetEOLAPIBaseURL(opts.EOLAPIBaseURL)
		log.Debugf("Configured EOL API base URL: %s", opts.EOLAPIBaseURL)
	}

	image := opts.Image
	reportPath := opts.Report
	targetPlatforms := opts.Platforms
	pkgTypes := opts.PkgTypes

	if opts.InputOCILayout != "" {
		if opts.OCIDir == "" {
			return fmt.Errorf("--input-oci-layout requires --oci-dir")
		}
		if opts.Push {
			return fmt.Errorf("--input-oci-layout cannot be used with --push")
		}
		if opts.Loader != "" {
			return fmt.Errorf("--input-oci-layout cannot be used with --loader")
		}
		source, err := ocilayout.Open(ctx, opts.InputOCILayout, opts.OCIDir, image)
		if err != nil {
			return err
		}
		opts.OCISource = source
	}

	// Parse and validate package types early
	pkgTypesList, err := parsePkgTypes(pkgTypes)
	if err != nil {
		return fmt.Errorf("invalid package types: %w", err)
	}

	// Validate that library package types require a scanner report
	reportProvided := reportPath != ""
	if err := validateLibraryPkgTypesRequireReport(pkgTypesList, reportProvided); err != nil {
		return err
	}

	// Handle empty report path - check if image is manifest list or single platform
	if reportPath == "" {
		// Discover platforms from the image reference to determine if it's multi-platform
		discoveredPlatforms, err := discoverPlatformsForOptions(ctx, opts)
		if err != nil {
			if opts.OCISource != nil {
				return fmt.Errorf("discover platforms in OCI layout input: %w", err)
			}
			// Failed to discover platforms - treat as single-platform image
			log.Warnf("Failed to discover platforms for image %s (treating as single-platform): %v", image, err)
			if len(targetPlatforms) > 0 {
				log.Info("Platform flag ignored when platform discovery fails")
			}

			// Fallback to default platform
			defaultPlatform := common.GetDefaultLinuxPlatform()
			patchPlatform := types.PatchPlatform{
				Platform:       defaultPlatform,
				ReportFile:     "",
				ShouldPreserve: false,
			}

			displaySingleArchPlan(opts, &patchPlatform)
			result, err := patchSingleArchImage(ctx, opts, patchPlatform, false, nil)
			if result != nil {
				logPatchSummary(result.Summary)
			}
			if err == nil && result != nil && result.PatchedRef != nil {
				log.Infof("Patched image (%s): %s\n", patchPlatform.OS+"/"+patchPlatform.Architecture, result.PatchedRef)
			}
			if err == nil {
				err = exportSinglePlatformOCI(ctx, opts, result, &patchPlatform)
			}
			return err
		}

		if len(discoveredPlatforms) <= 1 {
			// Single-platform image or multi-platform with only one valid platform
			log.Debugf("Detected single-platform image or multi-platform with single valid platform")
			if len(targetPlatforms) > 0 {
				log.Info("Platform flag ignored for single-platform image")
			}

			var patchPlatform types.PatchPlatform
			if len(discoveredPlatforms) == 1 {
				// Use the discovered platform from the manifest
				patchPlatform = discoveredPlatforms[0]
				log.Debugf("Using discovered platform from manifest: %s/%s", patchPlatform.OS, patchPlatform.Architecture)
			} else {
				// No platforms discovered, use default
				defaultPlatform := common.GetDefaultLinuxPlatform()
				patchPlatform = types.PatchPlatform{
					Platform:       defaultPlatform,
					ReportFile:     "",
					ShouldPreserve: false,
				}
			}

			displaySingleArchPlan(opts, &patchPlatform)
			result, err := patchSingleArchImage(ctx, opts, patchPlatform, false, nil)
			if result != nil {
				logPatchSummary(result.Summary)
			}
			if err == nil && result != nil && result.PatchedRef != nil {
				log.Infof("Patched image (%s): %s\n", patchPlatform.OS+"/"+patchPlatform.Architecture, result.PatchedRef)
			}
			if err == nil {
				err = exportSinglePlatformOCI(ctx, opts, result, &patchPlatform)
			}
			return err
		}

		log.Debugf("Detected multi-platform image with %d platforms", len(discoveredPlatforms))
		return patchMultiPlatformImage(ctx, opts, discoveredPlatforms)
	}

	// Check if reportPath exists
	if _, err := os.Stat(reportPath); os.IsNotExist(err) {
		return fmt.Errorf("report path %s does not exist", reportPath)
	}

	// Get file info to determine if it's a file or directory
	f, err := os.Stat(reportPath)
	if err != nil {
		return fmt.Errorf("failed to stat report path %s: %w", reportPath, err)
	}

	if f.IsDir() {
		// Handle directory - multi-platform patching
		log.Debugf("Using report directory: %s", reportPath)
		if len(targetPlatforms) > 0 {
			log.Info("Platform flag ignored when report directory is provided")
		}
		// For report directory, we pass nil as discoveredPlatforms - the function will discover them internally
		return patchMultiPlatformImage(ctx, opts, nil)
	}
	// Handle file - single-platform patching
	log.Debugf("Using report file: %s", reportPath)
	var parsedUpdates *unversioned.UpdateManifest
	if len(targetPlatforms) == 0 {
		parsedUpdates, err = report.TryParseScanReport(reportPath, opts.Scanner, pkgTypes, opts.LibraryPatchLevel)
		if err != nil {
			return err
		}
	}
	var patchPlatform types.PatchPlatform
	if parsedUpdates == nil {
		patchPlatform, err = resolveSingleReportPlatform(targetPlatforms)
	} else {
		patchPlatform, err = resolveSingleReportPlatformWithUpdates(targetPlatforms, parsedUpdates)
	}
	if err != nil {
		return err
	}
	if opts.OCISource != nil {
		discoveredPlatforms, discoverErr := discoverPlatformsForOptions(ctx, opts)
		if discoverErr != nil {
			return fmt.Errorf("discover platforms in OCI layout input: %w", discoverErr)
		}
		if len(discoveredPlatforms) > 1 {
			platforms, prepareErr := platformsForSingleReport(discoveredPlatforms, &patchPlatform, reportPath)
			if prepareErr != nil {
				return prepareErr
			}
			return patchPreparedMultiPlatformImage(ctx, opts, platforms)
		}
	}
	displaySingleArchPlan(opts, &patchPlatform)
	result, err := patchSingleArchImageWithUpdates(ctx, opts, patchPlatform, false, nil, parsedUpdates)
	if result != nil {
		logPatchSummary(result.Summary)
	}
	if err == nil && result != nil {
		log.Infof("Patched image (%s): %s\n", patchPlatform.OS+"/"+patchPlatform.Architecture, result.PatchedRef.String())
	}
	if err == nil {
		err = exportSinglePlatformOCI(ctx, opts, result, &patchPlatform)
	}
	return err
}

func discoverPlatformsForOptions(ctx context.Context, opts *types.Options) ([]types.PatchPlatform, error) {
	if opts.OCISource == nil {
		return buildkit.DiscoverPlatformsFromReference(opts.Image)
	}
	discovered, err := opts.OCISource.Platforms(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]types.PatchPlatform, 0, len(discovered))
	for _, platform := range discovered {
		result = append(result, types.PatchPlatform{Platform: platform})
	}
	return result, nil
}

func exportSinglePlatformOCI(ctx context.Context, opts *types.Options, result *types.PatchResult, platform *types.PatchPlatform) error {
	if opts.OCIDir == "" || opts.Push || result == nil {
		return nil
	}
	compression := opts.Compression
	if compression == "" {
		compression = DefaultLocalExportCompression
	}
	if err := buildkit.CreateOCILayoutFromResultsWithOptions(
		opts.OCIDir,
		[]types.PatchResult{*result},
		[]types.PatchPlatform{*platform},
		buildkit.OCILayoutExportOptions{
			Compression:      compression,
			ForceCompression: opts.ForceCompression,
			OutputReference:  result.PatchedRef.String(),
			BuildkitOpts: &buildkit.Opts{
				Addr:       opts.BkAddr,
				CACertPath: opts.BkCACertPath,
				CertPath:   opts.BkCertPath,
				KeyPath:    opts.BkKeyPath,
			},
			Atomic: opts.OCISource != nil,
		}.WithContext(ctx),
	); err != nil {
		return fmt.Errorf("failed to create OCI layout: %w", err)
	}
	return nil
}

func resolveSingleReportPlatform(targetPlatforms []string) (types.PatchPlatform, error) {
	return resolveSingleReportPlatformWithUpdates(targetPlatforms, nil)
}

func resolveSingleReportPlatformWithUpdates(targetPlatforms []string, updates *unversioned.UpdateManifest) (types.PatchPlatform, error) {
	if len(targetPlatforms) > 1 {
		return types.PatchPlatform{}, fmt.Errorf("a single report file can target only one platform; got %d: %s", len(targetPlatforms), strings.Join(targetPlatforms, ", "))
	}

	platform := common.GetDefaultLinuxPlatform()
	if len(targetPlatforms) == 1 {
		target := targetPlatforms[0]
		parsed, err := platforms.Parse(target)
		if err != nil {
			return types.PatchPlatform{}, fmt.Errorf("parse platform %q: %w", target, err)
		}
		platform = platforms.Normalize(parsed)
		if !isSupportedPatchPlatform(&platform) {
			return types.PatchPlatform{}, fmt.Errorf("unsupported platform %q; valid platforms: %s", target, strings.Join(validPlatforms, ", "))
		}
	} else if updates != nil {
		reportArch := strings.TrimSpace(updates.Metadata.Config.Arch)
		if reportArch != "" {
			platform = platforms.Normalize(ocispec.Platform{
				OS:           LINUX,
				Architecture: reportArch,
				Variant:      strings.TrimSpace(updates.Metadata.Config.Variant),
			})
			if !isSupportedPatchPlatform(&platform) {
				return types.PatchPlatform{}, fmt.Errorf("unsupported scan report platform %q; valid platforms: %s", platforms.Format(platform), strings.Join(validPlatforms, ", "))
			}
		}
	}
	if platform.OS != LINUX {
		platform.OS = LINUX
	}

	return types.PatchPlatform{Platform: platform}, nil
}

// logPatchSummary prints the patch summary if available.
func logPatchSummary(summary *unversioned.PatchSummary) {
	if summary == nil {
		return
	}
	log.Infof("Patch Summary: %d total, %d patched, %d skipped", summary.Total, summary.Patched, summary.Skipped)
}

// displaySingleArchPlan shows a patching plan for single-arch images.
func displaySingleArchPlan(opts *types.Options, platform *types.PatchPlatform) {
	// Use the same resolution logic as the actual patching to get accurate name
	patchedName := opts.Image + "-patched" // fallback
	if ref, err := reference.ParseNormalizedNamed(opts.Image); err == nil {
		if imageName, tag, err := common.ResolvePatchedImageName(ref, opts.PatchedTag, opts.Suffix); err == nil {
			patchedName = fmt.Sprintf("%s:%s", imageName, tag)
		}
	}

	plan := tui.PatchingPlan{
		TargetPlatform:     platform.String(),
		PatchedImageName:   patchedName,
		PreservedPlatforms: nil,
	}
	fmt.Fprintln(os.Stderr, tui.RenderPatchingPlan(plan))
}

// getErrorInfo maps common errors to styled error info.
func getErrorInfo(err error) tui.ErrorInfo {
	errStr := err.Error()

	// Check for common error patterns and provide helpful hints
	switch {
	case containsIgnoreCase(errStr, "no updates found"):
		return tui.ErrorInfo{
			Title:   "No Updates Available",
			Message: "No package updates were found for the specified vulnerabilities",
			Hint:    "The image may already be up-to-date or the vulnerabilities may not have fixes available",
		}
	case containsIgnoreCase(errStr, "failed to connect") || containsIgnoreCase(errStr, "connection refused"):
		return tui.ErrorInfo{
			Title:   "Connection Failed",
			Message: errStr,
			Hint:    "Check that BuildKit is running (docker buildx create --use) and accessible",
		}
	case containsIgnoreCase(errStr, "not found") || containsIgnoreCase(errStr, "404"):
		return tui.ErrorInfo{
			Title:   "Resource Not Found",
			Message: errStr,
			Hint:    "Check that the image name is correct and accessible",
		}
	case containsIgnoreCase(errStr, "unauthorized") || containsIgnoreCase(errStr, "401"):
		return tui.ErrorInfo{
			Title:   "Authentication Failed",
			Message: errStr,
			Hint:    "Try logging in with 'docker login' first",
		}
	case containsIgnoreCase(errStr, "EOL") || containsIgnoreCase(errStr, "end of life"):
		return tui.ErrorInfo{
			Title:   "End of Life OS Detected",
			Message: errStr,
			Hint:    "Consider upgrading to a supported OS version",
		}
	default:
		return tui.ErrorInfo{
			Title:   "Patch Failed",
			Message: errStr,
			Hint:    "",
		}
	}
}

// containsIgnoreCase checks if s contains substr (case-insensitive).
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
