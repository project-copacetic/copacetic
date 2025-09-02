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
	"github.com/project-copacetic/copacetic/pkg/buildkit"
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

	// Check if report is a directory by examining the extracted temp path
	// The extractReportFromContext function creates different temp paths:
	// - copa-frontend-report-* for single files
	// - copa-frontend-reports-* for directories
	if opts.Report != "" {
		// Check if it's a directory by looking for platform-specific JSON files
		if fi, err := os.Stat(opts.Report); err == nil && fi.IsDir() {
			// Try to discover platforms from the extracted directory
			entries, err := os.ReadDir(opts.Report)
			if err == nil {
				hasPlatformFiles := false
				for _, entry := range entries {
					if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
						// Check if filename matches platform pattern (e.g., linux-amd64.json)
						name := strings.TrimSuffix(entry.Name(), ".json")
						if strings.Contains(name, "-") {
							hasPlatformFiles = true
							break
						}
					}
				}
				if hasPlatformFiles {
					bklog.G(ctx).WithField("component", "copa-frontend").WithField("reportDir", opts.Report).Info("Detected report directory with platform files, using multiplatform patching")
					return f.buildMultiarch(ctx, opts)
				}
			}
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
			patchPlatforms, err := buildkit.DiscoverPlatformsFromReport(opts.Report, opts.Scanner)
			if err != nil {
				return nil, errors.Wrap(err, "failed to discover platforms from report directory")
			}

			// Convert PatchPlatform to ocispecs.Platform
			for _, pp := range patchPlatforms {
				targetPlatforms = append(targetPlatforms, pp.Platform)
			}

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
