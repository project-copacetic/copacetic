package helm

import (
	"testing"

	helmchart "helm.sh/helm/v3/pkg/chart"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ResolveImageValuePaths tests ---

func TestResolveImageValuePaths_SimpleImage(t *testing.T) {
	values := map[string]interface{}{
		"image": map[string]interface{}{
			"repository": "nginx",
			"tag":        "1.25.0",
		},
	}
	images := []ChartImage{{Repository: "nginx", Tag: "1.25.0"}}

	paths := ResolveImageValuePaths(values, images, nil)

	require.Len(t, paths, 1)
	assert.Equal(t, "nginx", paths[0].ImageRepo)
	assert.Equal(t, "image.repository", paths[0].RepositoryPath)
	assert.Equal(t, "image.tag", paths[0].TagPath)
}

func TestResolveImageValuePaths_RegistryPrefix(t *testing.T) {
	// Chart discovers "docker.io/library/nginx" but values.yaml has just "nginx"
	values := map[string]interface{}{
		"image": map[string]interface{}{
			"repository": "nginx",
			"tag":        "1.25.0",
		},
	}
	images := []ChartImage{{Repository: "docker.io/library/nginx", Tag: "1.25.0"}}

	paths := ResolveImageValuePaths(values, images, nil)

	require.Len(t, paths, 1)
	assert.Equal(t, "docker.io/library/nginx", paths[0].ImageRepo)
	assert.Equal(t, "image.repository", paths[0].RepositoryPath)
}

func TestResolveImageValuePaths_MultiComponent(t *testing.T) {
	values := map[string]interface{}{
		"controller": map[string]interface{}{
			"image": map[string]interface{}{
				"repository": "ingress-nginx/controller",
				"tag":        "v1.9.0",
			},
		},
		"backend": map[string]interface{}{
			"image": map[string]interface{}{
				"repository": "defaultbackend-amd64",
				"tag":        "1.5",
			},
		},
	}
	images := []ChartImage{
		{Repository: "ingress-nginx/controller", Tag: "v1.9.0"},
		{Repository: "defaultbackend-amd64", Tag: "1.5"},
	}

	paths := ResolveImageValuePaths(values, images, nil)

	require.Len(t, paths, 2)

	// Build a lookup for easier assertion
	pathMap := make(map[string]ValuePathMapping)
	for _, p := range paths {
		pathMap[p.ImageRepo] = p
	}

	assert.Equal(t, "controller.image.repository", pathMap["ingress-nginx/controller"].RepositoryPath)
	assert.Equal(t, "controller.image.tag", pathMap["ingress-nginx/controller"].TagPath)
	assert.Equal(t, "backend.image.repository", pathMap["defaultbackend-amd64"].RepositoryPath)
	assert.Equal(t, "backend.image.tag", pathMap["defaultbackend-amd64"].TagPath)
}

func TestResolveImageValuePaths_ExplicitOverride(t *testing.T) {
	values := map[string]interface{}{
		"customKey": map[string]interface{}{
			"repo": "myimage", // Non-standard key name — auto-detection won't find this
		},
	}
	images := []ChartImage{{Repository: "myimage", Tag: "1.0.0"}}
	explicit := map[string]string{
		"myimage": "customKey.repo-parent", // User provides the path
	}

	paths := ResolveImageValuePaths(values, images, explicit)

	require.Len(t, paths, 1)
	assert.Equal(t, "customKey.repo-parent.repository", paths[0].RepositoryPath)
	assert.Equal(t, "customKey.repo-parent.tag", paths[0].TagPath)
}

func TestResolveImageValuePaths_ExplicitTakesPriority(t *testing.T) {
	values := map[string]interface{}{
		"image": map[string]interface{}{
			"repository": "nginx",
			"tag":        "1.25.0",
		},
	}
	images := []ChartImage{{Repository: "nginx", Tag: "1.25.0"}}
	explicit := map[string]string{
		"nginx": "custom.path",
	}

	paths := ResolveImageValuePaths(values, images, explicit)

	require.Len(t, paths, 1)
	// Should use explicit path, not auto-detected
	assert.Equal(t, "custom.path.repository", paths[0].RepositoryPath)
}

func TestResolveImageValuePaths_NoMatch(t *testing.T) {
	values := map[string]interface{}{
		"config": map[string]interface{}{
			"setting": "value",
		},
	}
	images := []ChartImage{{Repository: "unknown-image", Tag: "1.0.0"}}

	paths := ResolveImageValuePaths(values, images, nil)

	assert.Empty(t, paths)
}

func TestResolveImageValuePaths_RepositoryWithoutTag(t *testing.T) {
	values := map[string]interface{}{
		"image": map[string]interface{}{
			"repository": "nginx",
			// No "tag" key
		},
	}
	images := []ChartImage{{Repository: "nginx", Tag: "latest"}}

	paths := ResolveImageValuePaths(values, images, nil)

	require.Len(t, paths, 1)
	assert.Equal(t, "image.repository", paths[0].RepositoryPath)
	assert.Equal(t, "", paths[0].TagPath) // No tag path detected
}

func TestResolveImageValuePaths_ReversePrefix(t *testing.T) {
	// values.yaml has full registry, but chart discovers short form
	values := map[string]interface{}{
		"image": map[string]interface{}{
			"repository": "docker.io/timberio/vector",
			"tag":        "0.53.0",
		},
	}
	images := []ChartImage{{Repository: "timberio/vector", Tag: "0.53.0"}}

	paths := ResolveImageValuePaths(values, images, nil)

	require.Len(t, paths, 1)
	assert.Equal(t, "timberio/vector", paths[0].ImageRepo)
	assert.Equal(t, "image.repository", paths[0].RepositoryPath)
}

// --- BuildPatchedChart tests ---

func TestBuildPatchedChart_Basic(t *testing.T) {
	original := &helmchart.Chart{
		Metadata: &helmchart.Metadata{
			APIVersion: "v2",
			Name:       "vector",
			Version:    "0.53.0",
		},
	}
	spec := ChartSourceSpec{
		Name:       "vector",
		Version:    "0.53.0",
		Repository: "oci://ghcr.io/vectordotdev/helm",
	}
	mappings := []ImageMapping{
		{
			OriginalRepo: "docker.io/timberio/vector",
			OriginalTag:  "0.53.0-distroless-libc",
			PatchedRepo:  "ghcr.io/myorg/vector",
			PatchedTag:   "0.53.0-debian-patched",
		},
	}
	valuePaths := []ValuePathMapping{
		{
			ImageRepo:      "docker.io/timberio/vector",
			RepositoryPath: "image.repository",
			TagPath:        "image.tag",
		},
	}

	ch, err := BuildPatchedChart(original, spec, mappings, valuePaths)
	require.NoError(t, err)

	// Check metadata
	assert.Equal(t, "vector-patched", ch.Metadata.Name)
	assert.Equal(t, "0.53.0-patched.1", ch.Metadata.Version)
	assert.Equal(t, "v2", ch.Metadata.APIVersion)
	assert.Equal(t, "application", ch.Metadata.Type)
	assert.Contains(t, ch.Metadata.Description, "Copa-patched version of vector")

	// Check annotations
	assert.Equal(t, "vector", ch.Metadata.Annotations["copa.sh/source-chart"])
	assert.Equal(t, "0.53.0", ch.Metadata.Annotations["copa.sh/source-version"])
	assert.Equal(t, "oci://ghcr.io/vectordotdev/helm", ch.Metadata.Annotations["copa.sh/source-repository"])
	assert.NotEmpty(t, ch.Metadata.Annotations["copa.sh/patched-at"])

	// Check dependency
	require.Len(t, ch.Metadata.Dependencies, 1)
	dep := ch.Metadata.Dependencies[0]
	assert.Equal(t, "vector", dep.Name)
	assert.Equal(t, "0.53.0", dep.Version)
	assert.Equal(t, "oci://ghcr.io/vectordotdev/helm", dep.Repository)

	// Check values override
	vectorVals, ok := ch.Values["vector"].(map[string]interface{})
	require.True(t, ok, "expected 'vector' key in values")
	imageVals, ok := vectorVals["image"].(map[string]interface{})
	require.True(t, ok, "expected 'image' key under 'vector'")
	assert.Equal(t, "ghcr.io/myorg/vector", imageVals["repository"])
	assert.Equal(t, "0.53.0-debian-patched", imageVals["tag"])
}

func TestBuildPatchedChart_MultipleImages(t *testing.T) {
	original := &helmchart.Chart{
		Metadata: &helmchart.Metadata{
			APIVersion: "v2",
			Name:       "myapp",
			Version:    "2.0.0",
		},
	}
	spec := ChartSourceSpec{
		Name:       "myapp",
		Version:    "2.0.0",
		Repository: "oci://ghcr.io/charts",
	}
	mappings := []ImageMapping{
		{OriginalRepo: "nginx", OriginalTag: "1.25.0", PatchedRepo: "ghcr.io/org/nginx", PatchedTag: "1.25.0-patched"},
		{OriginalRepo: "redis", OriginalTag: "7.2.0", PatchedRepo: "ghcr.io/org/redis", PatchedTag: "7.2.0-patched"},
	}
	valuePaths := []ValuePathMapping{
		{ImageRepo: "nginx", RepositoryPath: "web.image.repository", TagPath: "web.image.tag"},
		{ImageRepo: "redis", RepositoryPath: "cache.image.repository", TagPath: "cache.image.tag"},
	}

	ch, err := BuildPatchedChart(original, spec, mappings, valuePaths)
	require.NoError(t, err)

	appValsAny, ok := ch.Values["myapp"]
	require.True(t, ok)
	appVals, ok := appValsAny.(map[string]interface{})
	require.True(t, ok)

	webValsAny, ok := appVals["web"]
	require.True(t, ok)
	webVals, ok := webValsAny.(map[string]interface{})
	require.True(t, ok)
	webImageAny, ok := webVals["image"]
	require.True(t, ok)
	webImage, ok := webImageAny.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "ghcr.io/org/nginx", webImage["repository"])
	assert.Equal(t, "1.25.0-patched", webImage["tag"])

	cacheValsAny, ok := appVals["cache"]
	require.True(t, ok)
	cacheVals, ok := cacheValsAny.(map[string]interface{})
	require.True(t, ok)
	cacheImageAny, ok := cacheVals["image"]
	require.True(t, ok)
	cacheImage, ok := cacheImageAny.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "ghcr.io/org/redis", cacheImage["repository"])
	assert.Equal(t, "7.2.0-patched", cacheImage["tag"])
}

func TestBuildPatchedChart_NilChart(t *testing.T) {
	_, err := BuildPatchedChart(nil, ChartSourceSpec{}, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestBuildPatchedChart_NoMatchingMappings(t *testing.T) {
	original := &helmchart.Chart{
		Metadata: &helmchart.Metadata{
			APIVersion: "v2",
			Name:       "myapp",
			Version:    "1.0.0",
		},
	}
	spec := ChartSourceSpec{Name: "myapp", Version: "1.0.0", Repository: "oci://example.com/charts"}

	// Value paths exist but no matching mappings
	valuePaths := []ValuePathMapping{
		{ImageRepo: "orphan-image", RepositoryPath: "image.repository", TagPath: "image.tag"},
	}

	ch, err := BuildPatchedChart(original, spec, nil, valuePaths)
	require.NoError(t, err)
	// Values should be empty (no overrides to apply)
	assert.Empty(t, ch.Values)
}

// --- Helper function tests ---

func TestImageMatchesValue(t *testing.T) {
	tests := []struct {
		imageRepo string
		valueRepo string
		want      bool
	}{
		{"nginx", "nginx", true},
		{"docker.io/library/nginx", "nginx", true},
		{"nginx", "docker.io/library/nginx", true},
		{"docker.io/timberio/vector", "timberio/vector", true},
		{"timberio/vector", "docker.io/timberio/vector", true},
		{"nginx", "redis", false},
		{"nginx", "my-nginx", false},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.imageRepo+"_vs_"+tt.valueRepo, func(t *testing.T) {
			assert.Equal(t, tt.want, imageMatchesValue(tt.imageRepo, tt.valueRepo))
		})
	}
}

func TestSetNestedValue(t *testing.T) {
	m := make(map[string]interface{})
	setNestedValue(m, "a.b.c", "value")

	a, ok := m["a"].(map[string]interface{})
	require.True(t, ok)
	b, ok := a["b"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "value", b["c"])
}

func TestSetNestedValue_SingleLevel(t *testing.T) {
	m := make(map[string]interface{})
	setNestedValue(m, "key", "value")
	assert.Equal(t, "value", m["key"])
}

func TestFindRepositoryPaths_DeepNesting(t *testing.T) {
	values := map[string]interface{}{
		"global": map[string]interface{}{
			"image": map[string]interface{}{
				"registry": "docker.io", // Not a "repository" key — should be ignored
			},
		},
		"app": map[string]interface{}{
			"deployment": map[string]interface{}{
				"image": map[string]interface{}{
					"repository": "myapp",
					"tag":        "v1",
				},
			},
		},
	}

	candidates := findRepositoryPaths(values, "")
	require.Len(t, candidates, 1)
	assert.Equal(t, "app.deployment.image.repository", candidates[0].path)
	assert.Equal(t, "app.deployment.image.tag", candidates[0].tagPath)
	assert.Equal(t, "myapp", candidates[0].value)
}
