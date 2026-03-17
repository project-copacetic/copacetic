package integration

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed config-skip-test.yaml
var skipConfigTemplate string

// TestSkipAlreadyPatchedImages validates the skip functionality for bulk patching.
// It verifies that:
// 1. Images are patched on the first run.
// 2. Images are skipped on the second run (no vulnerabilities).
func TestSkipAlreadyPatchedImages(t *testing.T) {
	t.Setenv("GODEBUG", "netdns=go+netgo")
	ctx := context.Background()
	regContainer, registryHost, err := startLocalRegistry(ctx)
	require.NoError(t, err, "failed to start local registry")
	defer func() {
		if err := regContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	// Seed a single image for testing
	seedImage := "alpine:3.19.1"
	err = pushToLocalRegistry(seedImage, registryHost)
	require.NoError(t, err, "failed to seed local registry with %s", seedImage)
	t.Logf("Successfully seeded local registry with %s", seedImage)

	localAlpineRepo := fmt.Sprintf("%s/library/alpine", registryHost)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "copa-skip-config.yaml")

	configContent := strings.ReplaceAll(skipConfigTemplate, "__ALPINE_REPO__", localAlpineRepo)
	err = os.WriteFile(configPath, []byte(configContent), 0o600)
	require.NoError(t, err, "failed to write temporary config file")

	// First run: patch the image
	t.Log("=== First run: patching image ===")
	cmd := exec.Command(copaPath, "patch", "--config", configPath, "--debug", "--push")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "copa command failed on first run with output:\n%s", string(output))
	t.Logf("First run output: %s", string(output))

	// Verify the base patched tag exists
	tags := listRepoTags(t, registryHost, "library/alpine")
	assert.Contains(t, tags, "3.19.1-skip-test", "base patched tag should exist after first run")
	t.Log("✓ Base patched tag created successfully")

	// Scan the patched image to generate a report
	reportsDir := filepath.Join(tmpDir, "reports")
	err = os.MkdirAll(reportsDir, 0o755)
	require.NoError(t, err, "failed to create reports directory")

	patchedImage := fmt.Sprintf("%s:3.19.1-skip-test", localAlpineRepo)
	reportPath := filepath.Join(reportsDir, "alpine-patched.json")
	scanCmd := exec.Command("trivy", "image", "--format", "json", "--output", reportPath, "--scanners", "vuln", patchedImage)
	scanOutput, err := scanCmd.CombinedOutput()
	require.NoError(t, err, "trivy scan failed with output:\n%s", string(scanOutput))
	t.Logf("Generated vulnerability report at %s", reportPath)

	// Second run: should skip (no new vulnerabilities)
	t.Log("=== Second run: should skip patching ===")
	cmd = exec.Command(copaPath, "patch", "--config", configPath, "--debug", "--push", "-r", reportsDir)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "copa command failed on second run with output:\n%s", string(output))
	t.Logf("Second run output: %s", string(output))

	// Verify output contains "Skipped" status
	outputStr := string(output)
	assert.Contains(t, outputStr, "Skipped", "output should indicate image was skipped")
	assert.Contains(t, outputStr, "no fixable vulnerabilities", "output should explain why it was skipped")
	t.Log("✓ Image correctly skipped on second run")

	// Verify no new tags were created
	tagsAfterSkip := listRepoTags(t, registryHost, "library/alpine")
	assert.Equal(t, tags, tagsAfterSkip, "no new tags should be created when skipping")
	t.Log("✓ No new tags created during skip")

	// Verify all expected tags exist
	expectedTags := []string{
		"3.19.1",           // original
		"3.19.1-skip-test", // first patch
	}
	for _, expectedTag := range expectedTags {
		assert.Contains(t, tagsAfterSkip, expectedTag, "expected tag %s should exist", expectedTag)
	}
	t.Logf("✓ All %d expected tags verified", len(expectedTags))
}

func listRepoTags(t *testing.T, registryHost, repoPath string) []string {
	repoRef, err := name.NewRepository(fmt.Sprintf("%s/%s", registryHost, repoPath), name.Insecure)
	require.NoError(t, err)

	tags, err := remote.List(repoRef)
	require.NoError(t, err, "failed to list tags for repo %s", repoPath)

	return tags
}
