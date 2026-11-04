package helm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDownloadChartUsesOCIHelmPull(t *testing.T) {
	archive := testChartArchive(t, "app", "1.0.0", "image:\n  repository: nginx\n  tag: \"1\"\n")
	orig := RunHelm
	t.Cleanup(func() { RunHelm = orig })
	RunHelm = func(_ context.Context, args ...string) ([]byte, error) {
		assert.Equal(t, []string{"pull", "--destination", args[2], "--version", "1.0.0", "oci://example.com/charts/app"}, args)
		return nil, os.WriteFile(filepath.Join(args[2], "app-1.0.0.tgz"), archive, 0o600)
	}
	chart, err := DownloadChart(context.Background(), "app", "1.0.0", "oci://example.com/charts")
	require.NoError(t, err)
	image, ok := chart.Values["image"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "nginx", image["repository"])
}

func TestDownloadChartUsesHTTPHelmPull(t *testing.T) {
	archive := testChartArchive(t, "app", "1.0.0", "")
	orig := RunHelm
	t.Cleanup(func() { RunHelm = orig })
	RunHelm = func(_ context.Context, args ...string) ([]byte, error) {
		assert.Equal(t, "app", args[5])
		assert.Equal(t, []string{"--repo", "https://example.com/charts"}, args[6:])
		return nil, os.WriteFile(filepath.Join(args[2], "app-1.0.0.tgz"), archive, 0o600)
	}
	_, err := DownloadChart(context.Background(), "app", "1.0.0", "https://example.com/charts")
	require.NoError(t, err)
}

func TestRenderChartUsesIncludeCRDs(t *testing.T) {
	orig := RunHelm
	t.Cleanup(func() { RunHelm = orig })
	RunHelm = func(_ context.Context, args ...string) ([]byte, error) {
		assert.Equal(t, "template", args[0])
		assert.Equal(t, []string{"--include-crds"}, args[3:])
		return []byte("apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - image: nginx:1\n"), nil
	}
	chart := &Chart{Metadata: Metadata{Name: "app"}, Archive: testChartArchive(t, "app", "1.0.0", "")}
	rendered, err := RenderChart(context.Background(), chart)
	require.NoError(t, err)
	assert.Contains(t, rendered, "nginx:1")
}

func TestRunHelmPreservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := runHelm(ctx, "version")
	require.ErrorIs(t, err, context.Canceled)
}

func TestRunHelmReportsMissingCLI(t *testing.T) {
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	_, err := runHelm(context.Background(), "version")
	require.Error(t, err)
	assert.ErrorContains(t, err, "requires the helm CLI")
	t.Setenv("PATH", origPath)
}

func TestDiscoverChartImages(t *testing.T) {
	orig := RenderChart
	t.Cleanup(func() { RenderChart = orig })
	RenderChart = func(context.Context, *Chart) (string, error) {
		return "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - image: nginx:1\n", nil
	}
	images, err := DiscoverChartImages(context.Background(), &Chart{Metadata: Metadata{Name: "app"}}, nil)
	require.NoError(t, err)
	assert.Equal(t, []ChartImage{{Repository: "nginx", Tag: "1"}}, images)
}

func TestDiscoverChartImagesPropagatesRenderError(t *testing.T) {
	orig := RenderChart
	t.Cleanup(func() { RenderChart = orig })
	RenderChart = func(context.Context, *Chart) (string, error) { return "", errors.New("render failed") }
	_, err := DiscoverChartImages(context.Background(), &Chart{Metadata: Metadata{Name: "app"}}, nil)
	require.ErrorContains(t, err, "render failed")
}

func testChartArchive(t *testing.T, name, version, values string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gz)
	files := map[string]string{
		name + "/Chart.yaml":  "apiVersion: v2\nname: " + name + "\nversion: " + version + "\n",
		name + "/values.yaml": values,
	}
	for path, content := range files {
		require.NoError(t, tarWriter.WriteHeader(&tar.Header{Name: path, Mode: 0o600, Size: int64(len(content))}))
		_, err := tarWriter.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tarWriter.Close())
	require.NoError(t, gz.Close())
	return buffer.Bytes()
}
