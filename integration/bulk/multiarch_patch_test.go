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

	t.Log("Verifying multi-arch patched image...")
	patchedRefStr := fmt.Sprintf("%s/library/debian:12.4-slim-patched-e2e", registryHost)
	patchedRef, err := name.ParseReference(patchedRefStr, name.Insecure)
	require.NoError(t, err)

	index, err := remote.Index(patchedRef)
	require.NoError(t, err, "could not fetch the patched multi-arch manifest list")
	indexManifest, err := index.IndexManifest()
	require.NoError(t, err)

	var foundPlatforms []string
	for _, manifest := range indexManifest.Manifests {
		if manifest.Platform != nil {
			foundPlatforms = append(foundPlatforms, manifest.Platform.String())
		}
	}

	expectedPlatforms := []string{"linux/amd64", "linux/arm/v7"}
	assert.ElementsMatch(t, expectedPlatforms, foundPlatforms, "The platforms in the patched manifest did not match")
	t.Logf("Successfully verified multi-arch manifest contains platforms: %v", foundPlatforms)
}
