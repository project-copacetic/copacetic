package bulk

import (
	"context"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/helm"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRedisManifest = `apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - image: redis:7.0
`

func TestValidateChartOpts(t *testing.T) {
	tests := []struct {
		name string
		opts *types.Options
		want string
	}{
		{"valid", &types.Options{ChartName: "app", ChartVersion: "1", ChartRepo: "oci://example.com/charts", ChartRegistry: "oci://example.com/patched", Push: true}, ""},
		{"name", &types.Options{}, "chart name is required"},
		{"version", &types.Options{ChartName: "app"}, "chart version is required"},
		{"repo", &types.Options{ChartName: "app", ChartVersion: "1"}, "chart repository is required"},
		{"registry", &types.Options{ChartName: "app", ChartVersion: "1", ChartRepo: "oci://x"}, "chart registry is required"},
		{"oci", &types.Options{ChartName: "app", ChartVersion: "1", ChartRepo: "oci://x", ChartRegistry: "https://x", Push: true}, "oci://"},
		{"push", &types.Options{ChartName: "app", ChartVersion: "1", ChartRepo: "oci://x", ChartRegistry: "oci://x"}, "requires --push"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateChartOpts(tt.opts)
			if tt.want == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.want)
			}
		})
	}
}

func TestPatchChartEndToEnd(t *testing.T) {
	origDownload, origRender, origPackage, origPatch := helm.DownloadChart, helm.RenderChart, helm.PackageAndPushFunc, patchImage
	t.Cleanup(func() {
		helm.DownloadChart, helm.RenderChart, helm.PackageAndPushFunc, patchImage = origDownload, origRender, origPackage, origPatch
	})
	helm.DownloadChart = func(context.Context, string, string, string) (*helm.Chart, error) {
		return &helm.Chart{
			Metadata: helm.Metadata{Name: "app", Version: "1"},
			Values:   map[string]interface{}{"image": map[string]interface{}{"repository": "redis", "tag": "7.0"}},
			Archive:  []byte("chart"),
		}, nil
	}
	helm.RenderChart = func(context.Context, *helm.Chart) (string, error) { return testRedisManifest, nil }
	var patched, pushed string
	patchImage = func(_ context.Context, opts *types.Options) error { patched = opts.PatchedTag; return nil }
	helm.PackageAndPushFunc = func(_ context.Context, _ *helm.Chart, ref string) (string, error) { pushed = ref; return ref, nil }
	err := PatchChart(context.Background(), &types.Options{ChartName: "app", ChartVersion: "1", ChartRepo: "oci://example.com/charts", ChartRegistry: "oci://example.com/patched", Push: true})
	require.NoError(t, err)
	assert.Equal(t, "redis:7.0-patched", patched)
	assert.Contains(t, pushed, "oci://example.com/patched/app-patched:1-patched.")
}

func TestPatchChartStopsOnPatchFailure(t *testing.T) {
	origDownload, origRender, origPatch := helm.DownloadChart, helm.RenderChart, patchImage
	t.Cleanup(func() { helm.DownloadChart, helm.RenderChart, patchImage = origDownload, origRender, origPatch })
	helm.DownloadChart = func(context.Context, string, string, string) (*helm.Chart, error) {
		return &helm.Chart{Metadata: helm.Metadata{Name: "app", Version: "1"}}, nil
	}
	helm.RenderChart = func(context.Context, *helm.Chart) (string, error) { return testRedisManifest, nil }
	patchImage = func(context.Context, *types.Options) error { return assert.AnError }
	err := PatchChart(context.Background(), &types.Options{ChartName: "app", ChartVersion: "1", ChartRepo: "oci://x", ChartRegistry: "oci://x", Push: true})
	require.ErrorContains(t, err, "failed to patch")
}
