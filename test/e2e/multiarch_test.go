package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMultiArchPatch tests the multi-architecture patching functionality.
func TestMultiArchPatch(t *testing.T) {
	// Skip the test if running in CI without docker
	if os.Getenv("CI") != "" && !isDockerAvailable() {
		t.Skip("Skipping test in CI environment without Docker")
	}

	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "copa-e2e-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a reports directory
	reportsDir := filepath.Join(tempDir, "reports")
	err = os.Mkdir(reportsDir, 0o600)
	require.NoError(t, err)

	// Create test report files for different architectures
	createTestReport(t, reportsDir, "report-linux-amd64.json", createMockVulnReport("alpine", "3.15", "amd64"))
	createTestReport(t, reportsDir, "report-linux-arm64.json", createMockVulnReport("alpine", "3.15", "arm64"))

	// Pull a multi-arch image for testing
	// We'll use a small multi-arch image like Alpine
	cmd := exec.Command("docker", "pull", "alpine:3.15")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to pull test image: %s", output)

	// Run copa patch with the multi-arch options
	copaCmd := exec.Command(
		"copa", "patch",
		"--image", "alpine:3.15",
		"--report-dir", reportsDir,
		"--missing-report", "warn",
		"--tag", "alpine:3.15-test-patched",
	)

	output, err = copaCmd.CombinedOutput()
	require.NoError(t, err, "Copa patch command failed: %s", output)
	outputStr := string(output)
	t.Logf("Copa output: %s", outputStr)

	// We don't assert NoError here because it might fail due to missing actual reports,
	// but we still want to check that the right platforms were detected

	// Check that the command output indicates it detected multiple platforms
	assert.Contains(t, outputStr, "linux/amd64")
	assert.Contains(t, outputStr, "linux/arm64")

	// Check that image inspection was successful
	assert.Contains(t, outputStr, "Discovering platforms from image")

	// Verify that at least one platform was processed or skipped
	assert.True(t,
		strings.Contains(outputStr, "Patching platform") ||
			strings.Contains(outputStr, "Skipping platform"),
		"Output should mention patching or skipping platforms")
}

// Helper to check if Docker is available.
func isDockerAvailable() bool {
	cmd := exec.Command("docker", "info")
	err := cmd.Run()
	return err == nil
}

// Helper to create a test report file.
func createTestReport(t *testing.T, dir, filename, content string) {
	path := filepath.Join(dir, filename)
	err := os.WriteFile(path, []byte(content), 0o600)
	require.NoError(t, err)
}

// Helper to create a mock vulnerability report.
func createMockVulnReport(osType, osVersion, arch string) string {
	return `{
		"osType": "` + osType + `",
		"osVersion": "` + osVersion + `",
		"arch": "` + arch + `",
		"updates": [
			{
				"name": "apk-tools",
				"installedVersion": "2.12.7-r0",
				"fixedVersion": "2.12.7-r1",
				"vulnerabilityID": "CVE-2021-12345"
			}
		]
	}`
}
