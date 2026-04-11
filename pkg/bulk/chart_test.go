package bulk

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/helm"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	helmchart "helm.sh/helm/v3/pkg/chart"
	helmregistry "helm.sh/helm/v3/pkg/registry"
)

const testRedisManifest = `
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - image: redis:7.0
`

func TestValidateChartOpts(t *testing.T) {
	tests := []struct {
		name    string
		opts    *types.Options
		wantErr string
	}{
		{
			name:    "all fields valid",
			opts:    &types.Options{ChartName: "vector", ChartVersion: "0.53.0", ChartRepo: "oci://ghcr.io/vectordotdev/helm", ChartRegistry: "oci://ghcr.io/myorg/charts"},
			wantErr: "",
		},
		{
			name:    "missing chart name",
			opts:    &types.Options{ChartVersion: "0.53.0", ChartRepo: "oci://x", ChartRegistry: "oci://x"},
			wantErr: "chart name is required",
		},
		{
			name:    "missing chart version",
			opts:    &types.Options{ChartName: "v", ChartRepo: "oci://x", ChartRegistry: "oci://x"},
			wantErr: "chart version is required",
		},
		{
			name:    "missing chart repo",
			opts:    &types.Options{ChartName: "v", ChartVersion: "1.0", ChartRegistry: "oci://x"},
			wantErr: "chart repository is required",
		},
		{
			name:    "missing chart registry",
			opts:    &types.Options{ChartName: "v", ChartVersion: "1.0", ChartRepo: "oci://x"},
			wantErr: "chart registry is required",
		},
		{
			name:    "non-oci chart registry",
			opts:    &types.Options{ChartName: "v", ChartVersion: "1.0", ChartRepo: "oci://x", ChartRegistry: "https://bad"},
			wantErr: "oci://",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateChartOpts(tt.opts)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestPatchChart_EndToEnd(t *testing.T) {
	// Mock all external dependencies
	origDownload := helm.DownloadChart
	origRender := helm.RenderChart
	origSave := helm.SaveChart
	origPush := helm.PushChart
	origPatchImage := patchImage
	t.Cleanup(func() {
		helm.DownloadChart = origDownload
		helm.RenderChart = origRender
		helm.SaveChart = origSave
		helm.PushChart = origPush
		patchImage = origPatchImage
	})

	helm.DownloadChart = func(name, version, repository string) (*helmchart.Chart, error) {
		return &helmchart.Chart{
			Metadata: &helmchart.Metadata{Name: name, Version: version},
			Values: map[string]interface{}{
				"image": map[string]interface{}{
					"repository": "redis",
					"tag":        "7.0",
				},
			},
		}, nil
	}
	helm.RenderChart = func(ch *helmchart.Chart) (string, error) {
		return testRedisManifest, nil
	}

	var patchedImages []string
	patchImage = func(_ context.Context, opts *types.Options) error {
		patchedImages = append(patchedImages, opts.Image+" → "+opts.PatchedTag)
		return nil
	}

	var pushedRef string
	helm.SaveChart = func(ch *helmchart.Chart, outDir string) (string, error) {
		fakePath := filepath.Join(outDir, ch.Name()+"-"+ch.Metadata.Version+".tgz")
		_ = os.WriteFile(fakePath, []byte("fake-chart"), 0o600)
		return fakePath, nil
	}
	helm.PushChart = func(data []byte, ref string) (*helmregistry.PushResult, error) {
		pushedRef = ref
		return &helmregistry.PushResult{Ref: ref}, nil
	}

	opts := &types.Options{
		ChartName:     "mychart",
		ChartVersion:  "1.0.0",
		ChartRepo:     "oci://ghcr.io/charts",
		ChartRegistry: "oci://ghcr.io/myorg/charts",
		Scanner:       "trivy",
		PkgTypes:      "os",
	}

	err := PatchChart(context.Background(), opts)
	require.NoError(t, err)

	// Verify image was patched
	require.Len(t, patchedImages, 1)
	assert.Contains(t, patchedImages[0], "redis:7.0")
	assert.Contains(t, patchedImages[0], "ghcr.io/myorg/charts/redis:7.0-patched")

	// Verify chart was pushed
	assert.Equal(t, "oci://ghcr.io/myorg/charts/mychart-patched:1.0.0-patched.1", pushedRef)
}

func TestPatchChart_MultipleImages(t *testing.T) {
	origDownload := helm.DownloadChart
	origRender := helm.RenderChart
	origSave := helm.SaveChart
	origPush := helm.PushChart
	origPatchImage := patchImage
	t.Cleanup(func() {
		helm.DownloadChart = origDownload
		helm.RenderChart = origRender
		helm.SaveChart = origSave
		helm.PushChart = origPush
		patchImage = origPatchImage
	})

	helm.DownloadChart = func(name, version, repository string) (*helmchart.Chart, error) {
		return &helmchart.Chart{
			Metadata: &helmchart.Metadata{Name: name, Version: version},
			Values: map[string]interface{}{
				"web": map[string]interface{}{
					"image": map[string]interface{}{
						"repository": "nginx",
						"tag":        "1.25.0",
					},
				},
				"cache": map[string]interface{}{
					"image": map[string]interface{}{
						"repository": "redis",
						"tag":        "7.2.0",
					},
				},
			},
		}, nil
	}
	helm.RenderChart = func(ch *helmchart.Chart) (string, error) {
		return `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - image: nginx:1.25.0
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cache
spec:
  template:
    spec:
      containers:
        - image: redis:7.2.0
`, nil
	}

	var patchedCount int
	patchImage = func(_ context.Context, _ *types.Options) error {
		patchedCount++
		return nil
	}

	var pushedRef string
	helm.SaveChart = func(ch *helmchart.Chart, outDir string) (string, error) {
		fakePath := filepath.Join(outDir, ch.Name()+"-"+ch.Metadata.Version+".tgz")
		_ = os.WriteFile(fakePath, []byte("fake"), 0o600)
		return fakePath, nil
	}
	helm.PushChart = func(data []byte, ref string) (*helmregistry.PushResult, error) {
		pushedRef = ref
		return &helmregistry.PushResult{Ref: ref}, nil
	}

	opts := &types.Options{
		ChartName:     "myapp",
		ChartVersion:  "2.0.0",
		ChartRepo:     "oci://ghcr.io/charts",
		ChartRegistry: "oci://ghcr.io/myorg/charts",
		Scanner:       "trivy",
		PkgTypes:      "os",
	}

	err := PatchChart(context.Background(), opts)
	require.NoError(t, err)

	assert.Equal(t, 2, patchedCount)
	assert.Equal(t, "oci://ghcr.io/myorg/charts/myapp-patched:2.0.0-patched.1", pushedRef)
}

func TestPatchChart_NoImagesFound(t *testing.T) {
	origDownload := helm.DownloadChart
	origRender := helm.RenderChart
	t.Cleanup(func() {
		helm.DownloadChart = origDownload
		helm.RenderChart = origRender
	})

	helm.DownloadChart = func(name, version, repository string) (*helmchart.Chart, error) {
		return &helmchart.Chart{
			Metadata: &helmchart.Metadata{Name: name, Version: version},
		}, nil
	}
	helm.RenderChart = func(ch *helmchart.Chart) (string, error) {
		return `
apiVersion: v1
kind: ConfigMap
metadata:
  name: test
`, nil
	}

	opts := &types.Options{
		ChartName:     "empty-chart",
		ChartVersion:  "1.0.0",
		ChartRepo:     "oci://ghcr.io/test",
		ChartRegistry: "oci://ghcr.io/myorg/charts",
	}

	err := PatchChart(context.Background(), opts)
	require.NoError(t, err) // Should succeed but do nothing
}

func TestPatchChart_PatchFailure_StopsWithoutIgnoreErrors(t *testing.T) {
	origDownload := helm.DownloadChart
	origRender := helm.RenderChart
	origPatchImage := patchImage
	t.Cleanup(func() {
		helm.DownloadChart = origDownload
		helm.RenderChart = origRender
		patchImage = origPatchImage
	})

	helm.DownloadChart = func(name, version, repository string) (*helmchart.Chart, error) {
		return &helmchart.Chart{
			Metadata: &helmchart.Metadata{Name: name, Version: version},
		}, nil
	}
	helm.RenderChart = func(ch *helmchart.Chart) (string, error) {
		return testRedisManifest, nil
	}

	patchImage = func(_ context.Context, _ *types.Options) error {
		return assert.AnError
	}

	opts := &types.Options{
		ChartName:     "failing",
		ChartVersion:  "1.0.0",
		ChartRepo:     "oci://ghcr.io/test",
		ChartRegistry: "oci://ghcr.io/myorg/charts",
		IgnoreError:   false,
	}

	err := PatchChart(context.Background(), opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to patch")
}

func TestPatchChart_PatchFailure_ContinuesWithIgnoreErrors(t *testing.T) {
	origDownload := helm.DownloadChart
	origRender := helm.RenderChart
	origPatchImage := patchImage
	t.Cleanup(func() {
		helm.DownloadChart = origDownload
		helm.RenderChart = origRender
		patchImage = origPatchImage
	})

	helm.DownloadChart = func(name, version, repository string) (*helmchart.Chart, error) {
		return &helmchart.Chart{
			Metadata: &helmchart.Metadata{Name: name, Version: version},
		}, nil
	}
	helm.RenderChart = func(ch *helmchart.Chart) (string, error) {
		return testRedisManifest, nil
	}

	patchImage = func(_ context.Context, _ *types.Options) error {
		return assert.AnError
	}

	opts := &types.Options{
		ChartName:     "failing",
		ChartVersion:  "1.0.0",
		ChartRepo:     "oci://ghcr.io/test",
		ChartRegistry: "oci://ghcr.io/myorg/charts",
		IgnoreError:   true, // Continue despite patch failure
	}

	err := PatchChart(context.Background(), opts)
	require.NoError(t, err) // No error — but also no chart generated (0 mappings)
}

func TestPatchChart_Validates(t *testing.T) {
	err := PatchChart(context.Background(), &types.Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chart name is required")
}
