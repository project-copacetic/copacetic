package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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

func TestBulkPatchingEndToEnd(t *testing.T) {
	t.Setenv("GODEBUG", "netdns=go+netgo")
	ctx := context.Background()

	regContainer, registryHost, err := startLocalRegistry(ctx)
	require.NoError(t, err, "failed to start local registry")
	defer func() {
		if err := regContainer.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate container: %s", err.Error())
		}
	}()
	t.Logf("Local registry started at: %s", registryHost)

	seedImages := []string{
		"alpine:3.17.0",
		"alpine:3.18.0",
		"alpine:3.19.0",
		"alpine:3.19.1",
	}
	for _, img := range seedImages {
		err := pushToLocalRegistry(img, registryHost)
		require.NoError(t, err, "failed to seed local registry with %s", img)
	}
	t.Logf("Successfully seeded local registry with %d images", len(seedImages))

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "copa-bulk-config.yaml")

	localRepo := fmt.Sprintf("%s/library/alpine", registryHost)

	configContent := fmt.Sprintf(`
apiVersion: copa.sh/v1alpha1
kind: PatchConfig
images:
  - name: "alpine-test"
    image: "%s"
    tags:
      strategy: "pattern"
      pattern: "^3\\.1[7-9]\\.[0-9]+$"
      maxTags: 2
      exclude: ["3.18.0"]
    target:
      tag: "{{ .SourceTag }}-patched-e2e"
`, localRepo)

	err = os.WriteFile(configPath, []byte(configContent), 0600) //nolint:gofumpt
	require.NoError(t, err, "failed to write temporary config file")

	t.Logf("Running copa: %s patch --config %s", copaPath, configPath)

	cmd := exec.Command(copaPath, "patch", "--config", configPath, "--debug", "--push")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "copa command failed with output:\n%s", string(output))

	t.Logf("Copa Patch Output:\n%s", string(output))

	t.Log("verifying results..")

	repoRef, err := name.NewRepository(localRepo)
	require.NoError(t, err)

	tags, err := remote.List(repoRef)
	require.NoError(t, err, "failed to list tags from local registry after patch")

	var patchedTags []string
	for _, tag := range tags {
		if strings.HasSuffix(tag, "-patched-e2e") {
			patchedTags = append(patchedTags, tag)
		}
	}
	sort.Strings(patchedTags)

	expectedPatchedTags := []string{
		"3.19.0-patched-e2e",
		"3.19.1-patched-e2e",
	}

	assert.Equal(t, expectedPatchedTags, patchedTags, "The set of patched tags in the registry did not match expectations")
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
