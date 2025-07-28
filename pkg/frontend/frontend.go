package frontend

import (
	"context"
	"os"
	"strings"

	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/frontend/gateway/grpcclient"
	"github.com/moby/buildkit/util/appcontext"
	"github.com/pkg/errors"
)

const (
	// Frontend option keys.
	keyImage        = "image"
	keyReport       = "report"
	keyReportPath   = "report-path"
	keyScanner      = "scanner"
	keyIgnoreErrors = "ignore-errors"
	keyPlatform     = "platform"
	keyPkgMgr       = "package-manager"
	keyOfflineMode  = "offline-mode"
	keyCacheMode    = "cache-mode"
	keySecurityMode = "security-mode"
	keyMirror       = "package-mirror"
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
	// Parse frontend configuration
	config, err := ParseConfig(ctx, f.client)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse frontend configuration")
	}

	// Clean up temporary report file if created
	if config.Report != "" {
		defer func() {
			// Attempt cleanup, but don't fail the build if cleanup fails
			_ = cleanupTempFile(config.Report)
		}()
	}

	// Build the patched image
	st, err := f.buildPatchedImage(ctx, config)
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

// cleanupTempFile removes a temporary file if it was created by the frontend.
func cleanupTempFile(filePath string) error {
	// Only clean up files that look like our temp files
	if strings.Contains(filePath, "copa-report-") && strings.HasSuffix(filePath, ".json") {
		return os.Remove(filePath)
	}
	return nil // Don't remove files we didn't create
}

// Main entry point for the frontend.
func RunFrontend(_ []string) {
	if err := grpcclient.RunFromEnvironment(appcontext.Context(), Build); err != nil {
		panic(err)
	}
}
