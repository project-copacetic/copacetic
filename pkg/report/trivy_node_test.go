package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseTrivyReportWithNodePackages(t *testing.T) {
	parser := &TrivyParser{}
	manifest, err := parser.Parse("testdata/trivy_node_valid.json")

	assert.NoError(t, err)
	assert.NotNil(t, manifest)

	// Check OS packages
	assert.Equal(t, 1, len(manifest.Updates))
	assert.Equal(t, "protobuf-c", manifest.Updates[0].Name)
	assert.Equal(t, "1.3.3-r1", manifest.Updates[0].InstalledVersion)
	assert.Equal(t, "1.3.3-r2", manifest.Updates[0].FixedVersion)

	// Check Node.js packages
	assert.Equal(t, 2, len(manifest.NodeUpdates))

	// First Node package
	assert.Equal(t, "ansi-regex", manifest.NodeUpdates[0].Name)
	assert.Equal(t, "3.0.0", manifest.NodeUpdates[0].InstalledVersion)
	assert.Equal(t, "3.0.1", manifest.NodeUpdates[0].FixedVersion)
	assert.Equal(t, "CVE-2021-3807", manifest.NodeUpdates[0].VulnerabilityID)

	// Second Node package
	assert.Equal(t, "follow-redirects", manifest.NodeUpdates[1].Name)
	assert.Equal(t, "1.14.7", manifest.NodeUpdates[1].InstalledVersion)
	assert.Equal(t, "1.14.8", manifest.NodeUpdates[1].FixedVersion)
	assert.Equal(t, "CVE-2022-0536", manifest.NodeUpdates[1].VulnerabilityID)
}

func TestParseTrivyReportOnlyNodePackages(t *testing.T) {
	// Test case where only Node.js vulnerabilities exist
	parser := &TrivyParser{}
	manifest, err := parser.Parse("testdata/trivy_node_only.json")

	// This should succeed even without OS packages
	assert.NoError(t, err)
	assert.NotNil(t, manifest)
	assert.Equal(t, 0, len(manifest.Updates))
	assert.Greater(t, len(manifest.NodeUpdates), 0)
}
