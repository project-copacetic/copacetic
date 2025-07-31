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
	// Frontend option keys - matching CLI options
	keyImage        = "image"
	keyReport       = "report"
	keyReportPath   = "report-path"
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

// buildMultiarch handles multiarch builds by processing each platform separately
func (f *Frontend) buildMultiarch(ctx context.Context, opts *types.Options) (*gwclient.Result, error) {
	// Parse platforms
	var targetPlatforms []ocispecs.Platform
	for _, platformStr := range opts.Platforms {
		platform, err := platforms.Parse(platformStr)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse platform: %s", platformStr)
		}
		targetPlatforms = append(targetPlatforms, platform)
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

// cleanupTempFile removes a temporary file if it was created by the frontend.
func cleanupTempFile(filePath string) error {
	// Only clean up files that look like our temp files
	if strings.Contains(filePath, "copa-report-") && strings.HasSuffix(filePath, ".json") {
		return os.Remove(filePath)
	}
	return nil // Don't remove files we didn't create
}
