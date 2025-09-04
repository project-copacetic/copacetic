package integration

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
	err = pushToLocalRegistry(multiArchImage, registryHost)
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

	inspectCmd := exec.Command("docker", "manifest", "inspect", patchedRefStr)
	jsonOutput, err := inspectCmd.CombinedOutput()
	require.NoError(t, err, "docker manifest inspect command failed with output: %s", string(jsonOutput))

	var manifest struct {
		Manifests []struct {
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	err = json.Unmarshal(jsonOutput, &manifest)
	require.NoError(t, err, "failed to parse manifest JSON from Docker CLI")

	var foundPlatforms []string
	for _, m := range manifest.Manifests {
		if m.Platform.OS != "" {
			foundPlatforms = append(foundPlatforms, fmt.Sprintf("%s/%s", m.Platform.OS, m.Platform.Architecture))
		}
	}

	expectedPlatforms := []string{"linux/amd64", "linux/arm64"}
	assert.ElementsMatch(t, expectedPlatforms, foundPlatforms, "The platforms in the patched manifest did not match")
	t.Logf("Successfully verified multi-arch manifest contains platforms: %v", foundPlatforms)
}
