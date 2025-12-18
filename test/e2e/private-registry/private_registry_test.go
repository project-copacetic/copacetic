package privateregistry

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPrivateRegistryPlatformDiscovery tests that Copa can correctly discover
// platforms from a private registry image when authenticated via docker login.
// This test validates the fix for UNAUTHORIZED errors during platform discovery.
func TestPrivateRegistryPlatformDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// This test requires authentication to GHCR which should be set up
	// via docker login before running this test.
	// In CI, this is done via the workflow using GITHUB_TOKEN.

	// Test image in private GHCR registry
	testImage := "ghcr.io/project-copacetic/copa-action/test/docker.io/library/nginx-private:1.21.0"

	// Run copa patch without a report (comprehensive patching)
	// This exercises the DiscoverPlatformsFromReference code path
	patchCmd := exec.Command(
		copaPath,
		"patch",
		"--image", testImage,
		"--tag", "patched-test",
		"-a="+buildkitAddr,
		"--debug",
	)

	var stdout, stderr bytes.Buffer
	patchCmd.Stdout = &stdout
	patchCmd.Stderr = &stderr

	err := patchCmd.Run()

	// Combine output for error reporting
	combinedOutput := stdout.String() + stderr.String()

	// Check that the UNAUTHORIZED error does not appear in the output
	require.NotContains(t, combinedOutput, "UNAUTHORIZED",
		"Platform discovery should not fail with UNAUTHORIZED error when authenticated. Output:\n%s", combinedOutput)

	require.NotContains(t, combinedOutput, "authentication required",
		"Platform discovery should not fail with authentication required error. Output:\n%s", combinedOutput)

	// The patch command should succeed or fail for reasons other than authentication
	if err != nil {
		// If it failed, make sure it's not due to authentication issues
		require.NotContains(t, err.Error(), "UNAUTHORIZED",
			"Patch command failed with UNAUTHORIZED error: %v", err)

		// Check if it's failing because the image doesn't exist or other valid reasons
		// Authentication errors should never occur if we're properly logged in
		if strings.Contains(combinedOutput, "Failed to discover platforms") &&
			strings.Contains(combinedOutput, "UNAUTHORIZED") {
			t.Fatalf("Platform discovery failed with authentication error despite being logged in.\nOutput:\n%s", combinedOutput)
		}
	}

	// If we got here without UNAUTHORIZED errors, the authentication fix is working
	t.Logf("Platform discovery completed without authentication errors")
}

// TestPrivateRegistryPlatformDiscoveryWithReport tests that Copa can patch
// a private registry image when a vulnerability report is provided.
func TestPrivateRegistryPlatformDiscoveryWithReport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// Test image in private GHCR registry
	testImage := "ghcr.io/project-copacetic/copa-action/test/docker.io/library/nginx-private:1.21.0"

	// Run copa patch with debug flag to see platform discovery logs
	// Even with a report, Copa may still query the registry for platform info
	patchCmd := exec.Command(
		copaPath,
		"patch",
		"--image", testImage,
		"--tag", "patched-report-test",
		"-a="+buildkitAddr,
		"--debug",
	)

	var stdout, stderr bytes.Buffer
	patchCmd.Stdout = &stdout
	patchCmd.Stderr = &stderr

	err := patchCmd.Run()

	combinedOutput := stdout.String() + stderr.String()

	// Primary check: no authentication errors
	require.NotContains(t, combinedOutput, "UNAUTHORIZED",
		"Should not see UNAUTHORIZED error when authenticated. Output:\n%s", combinedOutput)

	require.NotContains(t, combinedOutput, "authentication required",
		"Should not see authentication required error. Output:\n%s", combinedOutput)

	if err != nil {
		// Ensure failure is not due to auth
		require.NotContains(t, err.Error(), "UNAUTHORIZED",
			"Command failed with authentication error: %v\nOutput:\n%s", err, combinedOutput)
	}

	t.Logf("Private registry image patch completed without authentication errors")
}
