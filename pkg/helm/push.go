package helm

import (
	"fmt"
	"os"

	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
	helmregistry "helm.sh/helm/v3/pkg/registry"
)

// SaveChart packages a chart to a .tgz archive in the given directory.
// It is a function variable to allow test injection.
var SaveChart = func(ch *helmchart.Chart, outDir string) (string, error) {
	return chartutil.Save(ch, outDir)
}

// PushChart pushes a packaged chart (.tgz bytes) to an OCI registry.
// The ref must be a full OCI reference (e.g., "oci://ghcr.io/myorg/charts/myapp:1.0.0").
// It is a function variable to allow test injection.
var PushChart = func(data []byte, ref string) (*helmregistry.PushResult, error) {
	client, err := helmregistry.NewClient(
		helmregistry.ClientOptEnableCache(true),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Helm registry client: %w", err)
	}
	return client.Push(data, ref)
}

// PackageAndPush packages a chart and pushes it to the given OCI reference.
// Returns the push result or an error.
func PackageAndPush(ch *helmchart.Chart, ociRef string) (*helmregistry.PushResult, error) {
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

	result, err := PushChart(data, ociRef)
	if err != nil {
		return nil, fmt.Errorf("failed to push chart to %s: %w", ociRef, err)
	}

	return result, nil
}
