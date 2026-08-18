package helm

import (
	"context"
	"fmt"
	"os"

	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
	helmregistry "helm.sh/helm/v3/pkg/registry"
)

// SaveChart packages a chart to a .tgz archive in the given directory.
// It is a function variable to allow test injection.
var SaveChart = chartutil.Save

// PushChart pushes a packaged chart to an OCI registry.
// It is a function variable to allow test injection.
var PushChart = func(ctx context.Context, data []byte, ref string) (*helmregistry.PushResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client, err := helmregistry.NewClient(
		helmregistry.ClientOptEnableCache(true),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Helm registry client: %w", err)
	}
	return client.Push(data, ref)
}

// PackageAndPush packages a chart and pushes it to the given OCI reference.
func PackageAndPush(ctx context.Context, ch *helmchart.Chart, ociRef string) (*helmregistry.PushResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tmpDir, err := os.MkdirTemp("", "copa-chart-push-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir for chart packaging: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	chartPath, err := SaveChart(ch, tmpDir)
	if err != nil {
		return nil, fmt.Errorf("failed to package chart %q: %w", ch.Name(), err)
	}

	data, err := os.ReadFile(chartPath) // #nosec G304 — path from controlled temp dir
	if err != nil {
		return nil, fmt.Errorf("failed to read packaged chart: %w", err)
	}

	result, err := PushChart(ctx, data, ociRef)
	if err != nil {
		return nil, fmt.Errorf("failed to push chart to %s: %w", ociRef, err)
	}

	return result, nil
}
