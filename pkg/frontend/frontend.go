package frontend

import (
	"context"

	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/frontend/gateway/grpcclient"
	"github.com/moby/buildkit/util/appcontext"
	"github.com/pkg/errors"
)

const (
	// Frontend option keys
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

// Frontend implements the BuildKit frontend interface for Copa
type Frontend struct {
	client         gwclient.Client
	scannerFactory *ScannerFactory
}

// Build is the main entry point for the frontend
func Build(ctx context.Context, client gwclient.Client) (*gwclient.Result, error) {
	f := &Frontend{
		client:         client,
		scannerFactory: NewScannerFactory(),
	}
	return f.build(ctx)
}

func (f *Frontend) build(ctx context.Context) (*gwclient.Result, error) {
	// Parse frontend configuration
	config, err := ParseConfig(ctx, f.client)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse frontend configuration")
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


// Main entry point for the frontend
func RunFrontend(args []string) {
	if err := grpcclient.RunFromEnvironment(appcontext.Context(), Build); err != nil {
		panic(err)
	}
}