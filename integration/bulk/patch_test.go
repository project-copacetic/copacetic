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
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

//go:embed config-test.yaml
var configTemplate string

// TestComprehensiveBulkPatching validates all tag strategies in a single end-to-end run.
func TestComprehensiveBulkPatching(t *testing.T) {
	t.Setenv("GODEBUG", "netdns=go+netgo")
	ctx := context.Background() //nolint:golint,ineffassign
	regContainer, registryHost, err := startLocalRegistry(ctx)
	require.NoError(t, err, "failed to start local registry")
	defer func() {
		if err := regContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()
	seedImages := []string{
		"nginx:1.25.0",
		"nginx:1.25.1",
		"nginx:1.25.2",
		"nginx:1.25.3",
		"alpine:3.18.0",
		"alpine:3.19.1",
		"ubuntu:22.04",
	}
	for _, img := range seedImages {
		err := pushToLocalRegistry(img, registryHost)
		require.NoError(t, err, "failed to seed local registry with %s", img)
	}
	t.Logf("Successfully seeded local registry with %d images", len(seedImages))

	localNginxRepo := fmt.Sprintf("%s/library/nginx", registryHost)
	localAlpineRepo := fmt.Sprintf("%s/library/alpine", registryHost)
	localUbuntuRepo := fmt.Sprintf("%s/library/ubuntu", registryHost)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "copa-bulk-config.yaml")

	replacer := strings.NewReplacer(
		"__NGINX_REPO__", localNginxRepo,
		"__ALPINE_REPO__", localAlpineRepo,
		"__UBUNTU_REPO__", localUbuntuRepo,
	)
	configContent := replacer.Replace(configTemplate)

	err = os.WriteFile(configPath, []byte(configContent), 0600) //nolint:gofumpt
	require.NoError(t, err, "failed to write temporary config file")

	t.Logf("Running copa binary against generated config: %s", configPath)

	cmd := exec.Command(copaPath, "patch", "--config", configPath, "--debug", "--push")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "copa command failed with output:\n%s", string(output))

	t.Logf("Copa command finished successfully. Output: %s", string(output))

	t.Log("Verifying results in local registry...")

	allPatchedTags := listAllPatchedTags(t, registryHost, []string{"library/nginx", "library/alpine", "library/ubuntu"})

	expectedPatchedTags := []string{
		"1.25.3-patched-e2e",
		"1.25.2-patched-e2e",
		"3.19.1-patched-e2e",
		"22.04-patched-e2e",
	}

	assert.ElementsMatch(t, expectedPatchedTags, allPatchedTags, "The set of patched tags in the registry did not match expectations")
	t.Logf("Successfully verified all %d patched tags.", len(allPatchedTags))
}

func listAllPatchedTags(t *testing.T, registryHost string, repos []string) []string {
	var allPatchedTags []string
	for _, repoPath := range repos {
		repoRef, err := name.NewRepository(fmt.Sprintf("%s/%s", registryHost, repoPath))
		require.NoError(t, err)

		tags, err := remote.List(repoRef)
		if err != nil {
			t.Logf("Could not list tags for repo %s (this may be expected): %v", repoPath, err)
			continue
		}

		for _, tag := range tags {
			if strings.HasSuffix(tag, "-patched-e2e") {
				allPatchedTags = append(allPatchedTags, tag)
			}
		}
	}
	return allPatchedTags
}

func startLocalRegistry(ctx context.Context) (testcontainers.Container, string, error) {
	const fixedPort = "37219"

	req := testcontainers.ContainerRequest{
		Image:        "registry:2",
		ExposedPorts: []string{"5000/tcp"},
		WaitingFor:   wait.ForListeningPort("5000/tcp").WithStartupTimeout(2 * time.Minute),
		Env: map[string]string{
			"REGISTRY_HTTP_ADDR":              "0.0.0.0:5000",
			"REGISTRY_STORAGE_DELETE_ENABLED": "true",
		},
		HostConfigModifier: func(hostConfig *container.HostConfig) {
			hostConfig.PortBindings = nat.PortMap{
				"5000/tcp": []nat.PortBinding{
					{
						HostIP:   "127.0.0.1",
						HostPort: fixedPort,
					},
				},
			}
		},
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, "", err
	}

	registryHost := fmt.Sprintf("127.0.0.1:%s", fixedPort)
	return container, registryHost, nil
}

func pushToLocalRegistry(publicImage, localRegistryHost string) error {
	ref, err := name.ParseReference(publicImage)
	if err != nil {
		return err
	}

	img, err := remote.Image(ref)
	if err != nil {
		return err
	}

	localTagStr := fmt.Sprintf("%s/%s", localRegistryHost, ref.Context().RepositoryStr())
	if identifier, ok := ref.(name.Tag); ok {
		localTagStr = fmt.Sprintf("%s:%s", localTagStr, identifier.TagStr())
	}

	localRef, err := name.ParseReference(localTagStr, name.Insecure)
	if err != nil {
		return err
	}

	return remote.Write(localRef, img)
}
