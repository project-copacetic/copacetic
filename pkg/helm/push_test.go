package helm

import (
	"os"
	"testing"

	helmchart "helm.sh/helm/v3/pkg/chart"
	helmregistry "helm.sh/helm/v3/pkg/registry"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackageAndPush(t *testing.T) {
	// Track calls to SaveChart and PushChart
	var savedChart *helmchart.Chart
	var savedDir string
	var pushedData []byte
	var pushedRef string

	origSave := SaveChart
	origPush := PushChart
	t.Cleanup(func() {
		SaveChart = origSave
		PushChart = origPush
	})

	// Create a real temp dir and write a minimal .tgz so ReadFile works
	SaveChart = func(ch *helmchart.Chart, outDir string) (string, error) {
		savedChart = ch
		savedDir = outDir
		// Write a fake .tgz file
		fakePath := outDir + "/test-chart-1.0.0.tgz"
		err := os.WriteFile(fakePath, []byte("fake-tgz-content"), 0o600)
		return fakePath, err
	}

	PushChart = func(data []byte, ref string) (*helmregistry.PushResult, error) {
		pushedData = data
		pushedRef = ref
		return &helmregistry.PushResult{Ref: ref}, nil
	}

	ch := &helmchart.Chart{
		Metadata: &helmchart.Metadata{
			APIVersion: "v2",
			Name:       "test-chart",
			Version:    "1.0.0",
		},
	}

	result, err := PackageAndPush(ch, "oci://ghcr.io/myorg/charts/test-chart:1.0.0")
	require.NoError(t, err)

	assert.Equal(t, "test-chart", savedChart.Name())
	assert.NotEmpty(t, savedDir)
	assert.Equal(t, []byte("fake-tgz-content"), pushedData)
	assert.Equal(t, "oci://ghcr.io/myorg/charts/test-chart:1.0.0", pushedRef)
	assert.Equal(t, "oci://ghcr.io/myorg/charts/test-chart:1.0.0", result.Ref)
}

func TestPackageAndPush_SaveError(t *testing.T) {
	origSave := SaveChart
	t.Cleanup(func() { SaveChart = origSave })

	SaveChart = func(_ *helmchart.Chart, _ string) (string, error) {
		return "", assert.AnError
	}

	ch := &helmchart.Chart{
		Metadata: &helmchart.Metadata{
			APIVersion: "v2",
			Name:       "fail-chart",
			Version:    "1.0.0",
		},
	}

	_, err := PackageAndPush(ch, "oci://example.com/charts/fail:1.0.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to package chart")
}

func TestPackageAndPush_PushError(t *testing.T) {
	origSave := SaveChart
	origPush := PushChart
	t.Cleanup(func() {
		SaveChart = origSave
		PushChart = origPush
	})

	SaveChart = func(_ *helmchart.Chart, outDir string) (string, error) {
		fakePath := outDir + "/chart-1.0.0.tgz"
		_ = os.WriteFile(fakePath, []byte("data"), 0o600)
		return fakePath, nil
	}
	PushChart = func(_ []byte, _ string) (*helmregistry.PushResult, error) {
		return nil, assert.AnError
	}

	ch := &helmchart.Chart{
		Metadata: &helmchart.Metadata{
			APIVersion: "v2",
			Name:       "chart",
			Version:    "1.0.0",
		},
	}

	_, err := PackageAndPush(ch, "oci://example.com/charts/chart:1.0.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to push chart")
}
