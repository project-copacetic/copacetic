package frontend

import (
	"context"
	"strings"

	"github.com/moby/buildkit/frontend/dockerui"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/util/bklog"
	"github.com/pkg/errors"

	"github.com/project-copacetic/copacetic/pkg/types"
)

const (
	trueStr = "true"
)

// ParseOptions parses the frontend options from the build context.
func ParseOptions(ctx context.Context, client gwclient.Client) (*types.Options, error) {
	// Wrap the client with dockerui for better Docker CLI compatibility
	// This provides automatic dockerignore handling and named context support
	c, err := dockerui.NewClient(client)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create dockerui client")
	}

	opts := c.BuildOpts()

	options := &types.Options{
		Scanner: "trivy", // default scanner
	}

	// Helper function to get option value, checking both direct and build-arg prefixed keys
	getOpt := func(key string) (string, bool) {
		// First try direct key (buildctl style)
		if v, ok := opts.Opts[key]; ok {
			return v, true
		}
		// Then try build-arg prefixed key (docker buildx style)
		if v, ok := opts.Opts["build-arg:"+key]; ok {
			return v, true
		}
		return "", false
	}

	// Parse base image
	if v, ok := getOpt(keyImage); ok {
		options.Image = v
	} else {
		return nil, errors.New("base image reference required via --opt image=<ref>")
	}

	// Parse scanner type
	if v, ok := getOpt(keyScanner); ok {
		options.Scanner = v
	}

	// Parse ignore errors flag
	if v, ok := getOpt(keyIgnoreErrors); ok {
		options.IgnoreError = v == trueStr || v == "1"
	}

	// Parse platforms (as string slice for multiarch support)
	if v, ok := getOpt(keyPlatform); ok {
		// Split comma-separated platforms
		options.Platforms = strings.Split(v, ",")
		bklog.G(ctx).WithField("component", "copa-frontend").WithField("platforms", options.Platforms).Debug("Parsed platforms")
	}

	// Parse vulnerability report
	if reportPath, ok := getOpt(keyReport); ok {
		bklog.G(ctx).WithField("component", "copa-frontend").WithField("reportPath", reportPath).Info("Vulnerability report provided, using report mode")

		// Extract the report from the BuildKit context
		extractedPath, err := extractReportFromContext(ctx, client, reportPath)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to extract report from context")
		}
		options.Report = extractedPath
	} else {
		// update all
		bklog.G(ctx).WithField("component", "copa-frontend").Info("No vulnerability report provided, using update-all mode")
	}

	// Parse patched tag
	if v, ok := getOpt(keyPatchedTag); ok {
		options.PatchedTag = v
	}

	// Parse suffix
	if v, ok := getOpt(keySuffix); ok {
		options.Suffix = v
	}

	// Parse output (for VEX document)
	if v, ok := getOpt(keyOutput); ok {
		options.Output = v
	}

	// Parse format (for VEX document)
	if v, ok := getOpt(keyFormat); ok {
		options.Format = v
	}

	return options, nil
}
