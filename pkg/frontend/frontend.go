package frontend

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/containerd/platforms"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/util/bklog"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/project-copacetic/copacetic/pkg/types"
)

const (
	// Frontend option keys - matching CLI options.
	keyImage        = "image"
	keyReport       = "report"
	keyScanner      = "scanner"
	keyIgnoreErrors = "ignore-errors"
	keyPlatform     = "platform"
	keyPatchedTag   = "tag"
	keySuffix       = "suffix"
	keyOutput       = "output"
	keyFormat       = "format"
)

// Frontend implements the BuildKit frontend interface for Copa.
type Frontend struct {
	client gwclient.Client
}

// Build is the main entry point for the frontend.
func Build(ctx context.Context, client gwclient.Client) (*gwclient.Result, error) {
	f := &Frontend{
		client: client,
	}
	return f.build(ctx)
}

func (f *Frontend) build(ctx context.Context) (*gwclient.Result, error) {
	bklog.G(ctx).WithField("component", "copa-frontend").Info("Frontend started")

	// Parse frontend configuration
	opts, err := ParseOptions(ctx, f.client)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse frontend configuration")
	}

	bklog.G(ctx).WithField("component", "copa-frontend").Debug("Configuration parsed successfully")

	// Clean up temporary report file if created
	if opts.Report != "" {
		defer func() {
			// Attempt cleanup, but don't fail the build if cleanup fails
			_ = cleanupTempFile(opts.Report)
		}()
	}

	// Check if report is a directory - if so, handle as multiplatform
	if opts.Report != "" {
		if fi, err := os.Stat(opts.Report); err == nil && fi.IsDir() {
			bklog.G(ctx).WithField("component", "copa-frontend").WithField("reportDir", opts.Report).Info("Detected report directory, using multiplatform patching")
			return f.buildMultiarch(ctx, opts)
		}
	}

	// Handle all platform builds through multiarch logic for consistency
	if len(opts.Platforms) > 0 {
		if len(opts.Platforms) > 1 {
			bklog.G(ctx).WithField("component", "copa-frontend").WithField("platforms", opts.Platforms).WithField("count", len(opts.Platforms)).Info("Building multiarch")
		} else {
			bklog.G(ctx).WithField("component", "copa-frontend").WithField("platform", opts.Platforms[0]).Info("Building single platform")
		}
		return f.buildMultiarch(ctx, opts)
	}

	// No platforms specified - use default build
	bklog.G(ctx).WithField("component", "copa-frontend").Info("Building for default platform")
	st, err := f.buildPatchedImage(ctx, opts, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build patched image")
	}

	// Solve and return the result
	def, err := st.Marshal(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal LLB")
	}

	res, err := f.client.Solve(ctx, gwclient.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to solve")
	}

	return res, nil
}

// buildMultiarch handles multiarch builds by processing each platform separately.
func (f *Frontend) buildMultiarch(ctx context.Context, opts *types.Options) (*gwclient.Result, error) {
	var targetPlatforms []ocispecs.Platform

	// If report is a directory, discover platforms from report files
	if opts.Report != "" {
		if fi, err := os.Stat(opts.Report); err == nil && fi.IsDir() {
			discoveredPlatforms, err := discoverPlatformsFromReportDirectory(opts.Report)
			if err != nil {
				return nil, errors.Wrap(err, "failed to discover platforms from report directory")
			}
			targetPlatforms = discoveredPlatforms
			bklog.G(ctx).WithField("component", "copa-frontend").WithField("platforms", targetPlatforms).Info("Discovered platforms from report directory")
		}
	}

	// Otherwise parse platforms from options
	if len(targetPlatforms) == 0 {
		for _, platformStr := range opts.Platforms {
			platform, err := platforms.Parse(platformStr)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse platform: %s", platformStr)
			}
			targetPlatforms = append(targetPlatforms, platform)
		}
	}

	// Create a new result that will hold all platform references
	res := gwclient.NewResult()

	// Build for each platform and add as separate references
	var expPlatforms exptypes.Platforms
	for _, platform := range targetPlatforms {
		st, err := f.buildPatchedImage(ctx, opts, &platform)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to build patched image for platform %s", platforms.Format(platform))
		}

		// Solve each platform individually to get a reference
		def, err := st.Marshal(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal LLB")
		}

		platformRes, err := f.client.Solve(ctx, gwclient.SolveRequest{
			Definition: def.ToPB(),
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to solve platform")
		}

		ref, err := platformRes.SingleRef()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get platform reference")
		}

		// Add the reference for this platform
		k := platforms.Format(platform)
		res.AddRef(k, ref)

		// Add platform metadata
		expPlatforms.Platforms = append(expPlatforms.Platforms, exptypes.Platform{
			ID:       k,
			Platform: platform,
		})
	}

	// Add platform metadata to result - always add for consistency
	dt, err := json.Marshal(expPlatforms)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal platforms")
	}
	res.AddMeta(exptypes.ExporterPlatformsKey, dt)

	return res, nil
}

// cleanupTempFile removes a temporary file or directory if it was created by the frontend.
func cleanupTempFile(filePath string) error {
	// Clean up temp files
	if strings.Contains(filePath, "copa-report-") && strings.HasSuffix(filePath, ".json") {
		return os.Remove(filePath)
	}
	// Clean up temp directories
	if strings.Contains(filePath, "copa-reports-") {
		return os.RemoveAll(filePath)
	}
	return nil // Don't remove files/directories we didn't create
}

// discoverPlatformsFromReportDirectory discovers platforms from report files in a directory.
func discoverPlatformsFromReportDirectory(reportDir string) ([]ocispecs.Platform, error) {
	var platforms []ocispecs.Platform

	entries, err := os.ReadDir(reportDir)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read report directory: %s", reportDir)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		// Extract platform from filename
		// Expected format: <os>-<arch>[-<variant>].json
		filename := strings.TrimSuffix(entry.Name(), ".json")
		parts := strings.Split(filename, "-")

		if len(parts) < 2 {
			continue // Skip files that don't match expected format
		}

		platform := ocispecs.Platform{
			OS:           parts[0],
			Architecture: parts[1],
		}

		if len(parts) > 2 {
			platform.Variant = strings.Join(parts[2:], "-")
		}

		platforms = append(platforms, platform)
	}

	if len(platforms) == 0 {
		return nil, errors.Errorf("no valid platform report files found in directory: %s", reportDir)
	}

	return platforms, nil
}
