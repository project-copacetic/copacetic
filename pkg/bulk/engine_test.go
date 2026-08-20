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
)

func TestBuildTargetRepository(t *testing.T) {
	tests := []struct {
		name           string
		sourceImage    string
		targetRegistry string
		expected       string
		expectError    bool
	}{
		{
			name:           "empty target registry uses source",
			sourceImage:    "quay.io/opstree/redis",
			targetRegistry: "",
			expected:       "quay.io/opstree/redis",
			expectError:    false,
		},
		{
			name:           "target registry with namespace",
			sourceImage:    "quay.io/opstree/redis",
			targetRegistry: "ghcr.io/myorg",
			expected:       "ghcr.io/myorg/redis",
			expectError:    false,
		},
		{
			name:           "docker.io library image",
			sourceImage:    "docker.io/library/nginx",
			targetRegistry: "ghcr.io/myorg",
			expected:       "ghcr.io/myorg/nginx",
			expectError:    false,
		},
		{
			name:           "short form image",
			sourceImage:    "nginx",
			targetRegistry: "ghcr.io/myorg",
			expected:       "ghcr.io/myorg/nginx",
			expectError:    false,
		},
		{
			name:           "multi-level namespace",
			sourceImage:    "registry.io/team/project/redis",
			targetRegistry: "ghcr.io/myorg",
			expected:       "ghcr.io/myorg/redis",
			expectError:    false,
		},
		{
			name:           "target registry with trailing slash",
			sourceImage:    "quay.io/opstree/redis",
			targetRegistry: "ghcr.io/myorg/",
			expected:       "ghcr.io/myorg/redis",
			expectError:    false,
		},
		{
			name:           "registry with port",
			sourceImage:    "registry.io:5000/team/redis",
			targetRegistry: "ghcr.io/myorg",
			expected:       "ghcr.io/myorg/redis",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildTargetRepository(tt.sourceImage, tt.targetRegistry)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestMergeTarget(t *testing.T) {
	tests := []struct {
		name         string
		globalTarget TargetSpec
		imageTarget  TargetSpec
		expected     TargetSpec
	}{
		{
			name:         "both empty",
			globalTarget: TargetSpec{},
			imageTarget:  TargetSpec{},
			expected:     TargetSpec{},
		},
		{
			name: "only global target",
			globalTarget: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-patched",
			},
			imageTarget: TargetSpec{},
			expected: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-patched",
			},
		},
		{
			name:         "only image target",
			globalTarget: TargetSpec{},
			imageTarget: TargetSpec{
				Registry: "ghcr.io/image",
				Tag:      "{{ .SourceTag }}-fixed",
			},
			expected: TargetSpec{
				Registry: "ghcr.io/image",
				Tag:      "{{ .SourceTag }}-fixed",
			},
		},
		{
			name: "image target overrides global registry",
			globalTarget: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-patched",
			},
			imageTarget: TargetSpec{
				Registry: "quay.io/override",
			},
			expected: TargetSpec{
				Registry: "quay.io/override",
				Tag:      "{{ .SourceTag }}-patched",
			},
		},
		{
			name: "image target overrides global tag",
			globalTarget: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-patched",
			},
			imageTarget: TargetSpec{
				Tag: "{{ .SourceTag }}-fixed",
			},
			expected: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-fixed",
			},
		},
		{
			name: "image target overrides both",
			globalTarget: TargetSpec{
				Registry: "ghcr.io/global",
				Tag:      "{{ .SourceTag }}-patched",
			},
			imageTarget: TargetSpec{
				Registry: "quay.io/override",
				Tag:      "{{ .SourceTag }}-fixed",
			},
			expected: TargetSpec{
				Registry: "quay.io/override",
				Tag:      "{{ .SourceTag }}-fixed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeTarget(tt.globalTarget, tt.imageTarget)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResolveChiselRelease(t *testing.T) {
	tests := []struct {
		name           string
		defaultRelease string
		imageRelease   string
		expected       string
	}{
		{name: "both omitted use inference"},
		{name: "bulk default", defaultRelease: "ubuntu-24.04", expected: "ubuntu-24.04"},
		{name: "image release without default", imageRelease: "/releases/ubuntu-24.04", expected: "/releases/ubuntu-24.04"},
		{name: "image release overrides bulk default", defaultRelease: "ubuntu-24.04", imageRelease: "https://example.com/releases.git#abc123", expected: "https://example.com/releases.git#abc123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, resolveChiselRelease(tt.defaultRelease, tt.imageRelease))
		})
	}
}

func TestResolveChartImagesWithCharts_RespectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := resolveChartImagesWithCharts(ctx, []ChartSpec{{Name: "chart", Version: "1.0.0", Repository: "oci://example.com/charts"}}, nil)
	require.ErrorIs(t, err, context.Canceled)
}

func TestMergeImageSpecsPreservesDiscoveredTags(t *testing.T) {
	config := PatchConfig{Images: []ImageSpec{{
		Name: "redis", Image: "redis", Tags: TagStrategy{Strategy: StrategyList, List: []string{"7.0"}},
	}}}
	merged := mergeImageSpecs(&config, []ImageSpec{
		{Name: "redis", Image: "redis", Tags: TagStrategy{Strategy: StrategyList, List: []string{"7.2"}}},
		{Name: "redis", Image: "redis", Tags: TagStrategy{Strategy: StrategyList, List: []string{"7.0"}}},
	})
	require.Len(t, merged.Images, 1)
	assert.Equal(t, []string{"7.0", "7.2"}, merged.Images[0].Tags.List)
}

func TestPatchFromConfigRequiresExperimentalModeForCharts(t *testing.T) {
	t.Setenv("COPA_EXPERIMENTAL", "")
	path := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(path, []byte(`
apiVersion: copa.sh/v1alpha1
kind: PatchConfig
charts:
  - name: app
    version: "1.0.0"
    repository: oci://example.com/charts
`), 0o600)
	require.NoError(t, err)
	err = PatchFromConfig(context.Background(), path, &types.Options{})
	require.ErrorContains(t, err, "COPA_EXPERIMENTAL=1")
}

func TestGenerateAndPushPatchedChartsRejectsFailedChartImage(t *testing.T) {
	resolution := chartResolution{
		Spec:  ChartSpec{Name: "app", Version: "1.0.0", Repository: "oci://example.com/charts"},
		Chart: &helmchart.Chart{Metadata: &helmchart.Metadata{Name: "app", Version: "1.0.0"}},
		Images: []helm.ChartImage{
			{Repository: "nginx", Tag: "1.0"},
			{Repository: "redis", Tag: "7.0"},
		},
	}
	mappings := []ChartImageMapping{{OriginalRepo: "nginx", OriginalTag: "1.0", PatchedRepo: "nginx", PatchedTag: "1.0-patched"}}
	config := PatchConfig{ChartTarget: &ChartTargetSpec{Registry: "oci://example.com/patched"}}

	err := generateAndPushPatchedCharts(context.Background(), []chartResolution{resolution}, mappings, map[string]struct{}{"redis:7.0": {}}, &config)
	require.ErrorContains(t, err, "not publishing wrapper")
}
