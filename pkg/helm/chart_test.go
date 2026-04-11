package helm

import (
	"testing"

	helmchart "helm.sh/helm/v3/pkg/chart"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoverChartImages(t *testing.T) {
	// Build a minimal in-memory Helm chart with known container images.
	nginxDeployment := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  template:
    spec:
      containers:
        - name: nginx
          image: docker.io/library/nginx:1.25.0
        - name: sidecar
          image: envoyproxy/envoy:v1.28.0
`
	redisStatefulSet := `
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis
spec:
  template:
    spec:
      containers:
        - name: redis
          image: redis:7.2.0
`

	mockChart := &helmchart.Chart{
		Metadata: &helmchart.Metadata{Name: "testchart", Version: "1.0.0"},
		Templates: []*helmchart.File{
			{Name: "templates/deployment.yaml", Data: []byte(nginxDeployment)},
			{Name: "templates/statefulset.yaml", Data: []byte(redisStatefulSet)},
		},
	}

	// Override RenderChart to return combined templates directly (no Helm SDK rendering needed).
	origRender := RenderChart
	t.Cleanup(func() { RenderChart = origRender })
	RenderChart = func(ch *helmchart.Chart) (string, error) {
		var parts []string
		for _, tmpl := range ch.Templates {
			parts = append(parts, string(tmpl.Data))
		}
		return join(parts, "\n---\n"), nil
	}

	images, err := DiscoverChartImages(mockChart, nil)
	require.NoError(t, err)
	assert.ElementsMatch(t, []ChartImage{
		{Repository: "docker.io/library/nginx", Tag: "1.25.0"},
		{Repository: "envoyproxy/envoy", Tag: "v1.28.0"},
		{Repository: "redis", Tag: "7.2.0"},
	}, images)
}

func TestDiscoverChartImages_WithOverrides(t *testing.T) {
	manifest := `
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - image: docker.io/timberio/vector:0.53.0-distroless-libc
`
	mockChart := &helmchart.Chart{
		Metadata:  &helmchart.Metadata{Name: "testchart", Version: "1.0.0"},
		Templates: []*helmchart.File{{Name: "templates/deploy.yaml", Data: []byte(manifest)}},
	}

	origRender := RenderChart
	t.Cleanup(func() { RenderChart = origRender })
	RenderChart = func(ch *helmchart.Chart) (string, error) {
		return string(ch.Templates[0].Data), nil
	}

	overrides := map[string]OverrideSpec{
		"timberio/vector": {From: "distroless-libc", To: "debian"},
	}

	images, err := DiscoverChartImages(mockChart, overrides)
	require.NoError(t, err)
	require.Len(t, images, 1)
	assert.Equal(t, "0.53.0-debian", images[0].Tag)
}

func TestDiscoverChartImages_EmptyChart(t *testing.T) {
	mockChart := &helmchart.Chart{
		Metadata:  &helmchart.Metadata{Name: "crds-only", Version: "1.0.0"},
		Templates: []*helmchart.File{},
	}

	origRender := RenderChart
	t.Cleanup(func() { RenderChart = origRender })
	RenderChart = func(ch *helmchart.Chart) (string, error) {
		return "", nil
	}

	images, err := DiscoverChartImages(mockChart, nil)
	require.NoError(t, err)
	assert.Empty(t, images)
}

// join concatenates strings with a separator, helper for tests.
func join(parts []string, sep string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += sep
		}
		result += p
	}
	return result
}
