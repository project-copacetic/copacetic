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
