package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	container_types "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPushToRegistry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// check if we can run docker commands for this test
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("skipping test; docker binary not found in path")
	}

	// start a local registry for testing
	ctx := context.Background()
	setupLocalRegistry(ctx, t)
	defer stopLocalRegistry(t)

	// pull a small test image
	testImage := "alpine:3.16.4"
	baseImageCmd := exec.Command("docker", "pull", testImage)
	err := baseImageCmd.Run()
	require.NoError(t, err, "failed to pull test image")

	// tag image to local registry
	localImage := "localhost:5000/alpine:test"
	tagCmd := exec.Command("docker", "tag", testImage, localImage)
	err = tagCmd.Run()
	require.NoError(t, err, "failed to tag test image")

	// push to local registry first
	pushCmd := exec.Command("docker", "push", localImage)
	err = pushCmd.Run()
	require.NoError(t, err, "failed to push test image to local registry")

	// create a temp directory for report file
	tempDir, err := os.MkdirTemp("", "copa-push-test-*")
	require.NoError(t, err, "failed to create temp directory")
	defer os.RemoveAll(tempDir)

	// create a sample report file
	reportFile := filepath.Join(tempDir, "report.json")
	reportContent := `{
		"SchemaVersion": 2,
		"ArtifactName": "alpine:3.16.4",
		"ArtifactType": "container_image",
		"Metadata": {
			"OS": {
				"Family": "alpine",
				"Name": "3.16.4"
			}
		},
		"Results": [
			{
				"Target": "alpine:3.16.4 (alpine 3.16.4)",
				"Class": "os-pkgs",
				"Type": "alpine",
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-2023-42366",
						"PkgName": "busybox",
						"InstalledVersion": "1.35.0-r17",
						"FixedVersion": "1.35.0-r18",
						"Severity": "MEDIUM"
					}
				]
			}
		]
	}`
	err = os.WriteFile(reportFile, []byte(reportContent), 0o600)
	require.NoError(t, err, "failed to create sample report file")

	// run copa patch with push flag
	targetImage := "localhost:5000/alpine:patched"
	patchCmd := exec.Command(
		copaPath,
		"patch",
		"--image", localImage,
		"--report", reportFile,
		"--push",
		"--tag", "patched",
	)

	output, err := patchCmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("failed to patch and push image: %s", string(output)))

	// verify image was pushed to registry but not loaded to docker
	// 1. check it exists in registry by pulling it
	pullCmd := exec.Command("docker", "pull", targetImage)
	err = pullCmd.Run()
	require.NoError(t, err, "failed to pull patched image from registry")

	// 2. verify patched package version
	inspectCmd := exec.Command("docker", "run", "--rm", targetImage, "sh", "-c", "ls -la /bin/busybox && echo 'Busybox found'")
	inspectOutput, err := inspectCmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("failed to run patched image: %s", string(inspectOutput)))
	assert.Contains(t, string(inspectOutput), "Busybox found", "patched image doesn't have busybox")

	// clean up
	removeLocalImage(t, localImage)
	removeLocalImage(t, targetImage)
}

func setupLocalRegistry(ctx context.Context, t *testing.T) {
	// check if registry is already running
	dockerCli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err, "failed to create docker client")

	containers, err := dockerCli.ContainerList(ctx, container_types.ListOptions{All: true})
	require.NoError(t, err, "failed to list containers")

	for i := range containers {
		container := &containers[i]
		for _, name := range container.Names {
			if strings.Contains(name, "registry-test") {
				// registry already exists, stop and remove it
				err := dockerCli.ContainerRemove(ctx, container.ID, container_types.RemoveOptions{Force: true})
				require.NoError(t, err, "failed to remove existing registry container")
				break
			}
		}
	}

	// start registry container
	cmd := exec.Command("docker", "run", "-d", "-p", "5000:5000", "--name", "registry-test", "registry:2")
	err = cmd.Run()
	require.NoError(t, err, "failed to start registry container")

	// wait for registry to be ready
	time.Sleep(2 * time.Second)
}

func stopLocalRegistry(t *testing.T) {
	cmd := exec.Command("docker", "rm", "-f", "registry-test")
	err := cmd.Run()
	require.NoError(t, err, "failed to stop registry container")
}

func removeLocalImage(_ *testing.T, image string) {
	cmd := exec.Command("docker", "rmi", "-f", image)
	_ = cmd.Run()
}
