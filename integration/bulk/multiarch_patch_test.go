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

	"github.com/stretchr/testify/require"
)

//go:embed config-multiarch.yaml
var multiArchConfigTemplate string

func TestMultiArchBulkPatching(t *testing.T) {
	t.Setenv("GODEBUG", "netdns=go+netgo")
	ctx := context.Background()

	regContainer, registryHost, err := startLocalRegistry(ctx)
	require.NoError(t, err, "failed to start local registry")
	defer func() {
		if err := regContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()
	t.Logf("Local registry started at: %s", registryHost)

	multiArchImage := "debian:12.4-slim"

	err = seedMultiArchImageWithDocker(multiArchImage, registryHost)
	require.NoError(t, err, "failed to seed local registry with %s", multiArchImage)
	t.Logf("Successfully seeded local registry with %s", multiArchImage)

	localDebianRepo := fmt.Sprintf("%s/library/debian", registryHost)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "copa-multiarch.yaml")

	configContent := strings.Replace(multiArchConfigTemplate, "__DEBIAN_REPO__", localDebianRepo, 1)
	err = os.WriteFile(configPath, []byte(configContent), 0600) //nolint:gofumpt
	require.NoError(t, err, "failed to write temporary config file")

	cmd := exec.Command(copaPath, "patch", "--config", configPath, "--debug", "--push", "--timeout=20m")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "copa command failed with output:\n%s", string(output))
	t.Logf("Copa command finished successfully.")

	t.Log("Verifying multi-arch patched image using Docker CLI...")
	patchedRefStr := fmt.Sprintf("%s/library/debian:12.4-slim-patched-e2e", registryHost)

	err = verifyPatchedImageExists(patchedRefStr, t)
	require.NoError(t, err, "failed to verify patched image exists")

	t.Logf("Successfully verified patched image: %s", patchedRefStr)
}

// seedMultiArchImageWithDocker uses Docker CLI to pull and push multi-arch images.
func seedMultiArchImageWithDocker(publicImage, localRegistryHost string) error {
	// Pull the multi-arch image
	pullCmd := exec.Command("docker", "pull", publicImage)
	pullOutput, err := pullCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to pull %s: %w, output: %s", publicImage, err, string(pullOutput))
	}

	parts := strings.Split(publicImage, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid image format: %s", publicImage)
	}
	imageName := parts[0]
	tag := parts[1]

	if !strings.Contains(imageName, "/") {
		imageName = "library/" + imageName
	}

	localImageRef := fmt.Sprintf("%s/%s:%s", localRegistryHost, imageName, tag)

	tagCmd := exec.Command("docker", "tag", publicImage, localImageRef)
	tagOutput, err := tagCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to tag %s as %s: %w, output: %s", publicImage, localImageRef, err, string(tagOutput))
	}

	pushCmd := exec.Command("docker", "push", localImageRef)
	pushOutput, err := pushCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to push %s to local registry: %w, output: %s", localImageRef, err, string(pushOutput))
	}

	return nil
}

// verifyPatchedImageExists uses Docker CLI to verify the patched image exists and is accessible.
func verifyPatchedImageExists(imageRef string, t *testing.T) error {
	pullCmd := exec.Command("docker", "pull", imageRef)
	pullOutput, err := pullCmd.CombinedOutput()
	if err == nil {
		t.Logf("Successfully pulled patched image: %s", imageRef)
		return nil
	}
	t.Logf("Pull failed (may be expected for local registry): %s", string(pullOutput))

	inspectCmd := exec.Command("docker", "buildx", "imagetools", "inspect", imageRef)
	inspectOutput, err := inspectCmd.CombinedOutput()
	if err == nil {
		t.Logf("Successfully inspected patched image with buildx: %s", imageRef)
		if strings.Contains(string(inspectOutput), "linux/amd64") || strings.Contains(string(inspectOutput), "MediaType") {
			return nil
		}
	}
	t.Logf("Buildx inspect failed: %s", string(inspectOutput))

	basicCmd := exec.Command("docker", "image", "inspect", imageRef)
	basicOutput, err := basicCmd.CombinedOutput()
	if err == nil {
		t.Logf("Successfully verified image exists locally: %s", imageRef)
		return nil
	}
	t.Logf("Basic inspect failed: %s", string(basicOutput))

	return fmt.Errorf("could not verify patched image exists using any method")
}
