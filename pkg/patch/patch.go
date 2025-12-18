package patch

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/moby/buildkit/util/progress/progressui"
	log "github.com/sirupsen/logrus"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/tui"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

// for testing.
var (
	bkNewClient = buildkit.NewClient
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

	ch := make(chan error)
	defer close(ch)

	go func() {
		ch <- patchWithContext(timeoutCtx, ch, opts)
	}()

	select {
	case err := <-ch:
		if err != nil {
			// Display styled error
			fmt.Fprintln(os.Stderr, tui.RenderError(getErrorInfo(err)))
		}
		return err
	case <-timeoutCtx.Done():
		// add a grace period for long running deferred cleanup functions to complete
		<-time.After(1 * time.Second)

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
func patchWithContext(ctx context.Context, ch chan error, opts *types.Options) error {
	// Configure EOL API if provided
	if opts.EOLAPIBaseURL != "" {
		utils.SetEOLAPIBaseURL(opts.EOLAPIBaseURL)
		log.Debugf("Configured EOL API base URL: %s", opts.EOLAPIBaseURL)
	}

	image := opts.Image
	reportPath := opts.Report
	targetPlatforms := opts.Platforms
	pkgTypes := opts.PkgTypes

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
		discoveredPlatforms, err := buildkit.DiscoverPlatformsFromReference(image)
		if err != nil {
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

			displaySingleArchPlan(opts, patchPlatform)
			result, err := patchSingleArchImage(ctx, ch, opts, patchPlatform, false)
			if err == nil && result != nil && result.PatchedRef != nil {
				log.Infof("Patched image (%s): %s\n", patchPlatform.OS+"/"+patchPlatform.Architecture, result.PatchedRef)
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

			displaySingleArchPlan(opts, patchPlatform)
			result, err := patchSingleArchImage(ctx, ch, opts, patchPlatform, false)
			if err == nil && result != nil && result.PatchedRef != nil {
				log.Infof("Patched image (%s): %s\n", patchPlatform.OS+"/"+patchPlatform.Architecture, result.PatchedRef)
			}
			return err
		}

		log.Debugf("Detected multi-platform image with %d platforms", len(discoveredPlatforms))
		return patchMultiPlatformImage(ctx, ch, opts, discoveredPlatforms)
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
		return patchMultiPlatformImage(ctx, ch, opts, nil)
	}
	// Handle file - single-platform patching
	log.Debugf("Using report file: %s", reportPath)
	defaultPlatform := common.GetDefaultLinuxPlatform()
	patchPlatform := types.PatchPlatform{
		Platform: defaultPlatform,
	}
	if patchPlatform.OS != LINUX {
		patchPlatform.OS = LINUX
	}
	displaySingleArchPlan(opts, patchPlatform)
	result, err := patchSingleArchImage(ctx, ch, opts, patchPlatform, false)
	if err == nil && result != nil {
		log.Infof("Patched image (%s): %s\n", patchPlatform.OS+"/"+patchPlatform.Architecture, result.PatchedRef.String())
	}
	return err
}

// displaySingleArchPlan shows a patching plan for single-arch images.
func displaySingleArchPlan(opts *types.Options, platform types.PatchPlatform) {
	patchedName := opts.PatchedTag
	if patchedName == "" {
		patchedName = opts.Image + "-patched"
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
	case contains(errStr, "no updates found"):
		return tui.ErrorInfo{
			Title:   "No Updates Available",
			Message: "No package updates were found for the specified vulnerabilities",
			Hint:    "The image may already be up-to-date or the vulnerabilities may not have fixes available",
		}
	case contains(errStr, "failed to connect") || contains(errStr, "connection refused"):
		return tui.ErrorInfo{
			Title:   "Connection Failed",
			Message: errStr,
			Hint:    "Check that BuildKit is running (docker buildx create --use) and accessible",
		}
	case contains(errStr, "not found") || contains(errStr, "404"):
		return tui.ErrorInfo{
			Title:   "Resource Not Found",
			Message: errStr,
			Hint:    "Check that the image name is correct and accessible",
		}
	case contains(errStr, "unauthorized") || contains(errStr, "401"):
		return tui.ErrorInfo{
			Title:   "Authentication Failed",
			Message: errStr,
			Hint:    "Try logging in with 'docker login' first",
		}
	case contains(errStr, "EOL") || contains(errStr, "end of life"):
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

// contains checks if s contains substr (case-insensitive).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(substr) == 0 ||
		(len(s) > 0 && containsLower(s, substr)))
}

func containsLower(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if matchLower(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func matchLower(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
