package push

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
	testImage := "docker.io/library/nginx:1.21.6"
	localImage := "localhost:5000/nginx:test"

	pushCmd := exec.Command("oras", "cp", testImage, localImage)
	out, err := pushCmd.CombinedOutput()
	require.NoErrorf(t, err, "oras cp failed:\n%s", string(out))

	// create a temp directory for report file
	tempDir, err := os.MkdirTemp("", "copa-push-test-*")
	require.NoError(t, err, "failed to create temp directory")
	defer os.RemoveAll(tempDir)

	// create a sample report file
	reportFile := filepath.Join(tempDir, "report.json")
	reportContent := `{
		"SchemaVersion": 2,
		"ArtifactName": "docker.io/library/nginx:1.21.6",
		"ArtifactType": "container_image",
		"Metadata": {
			"OS": {
				"Family": "debian",
				"Name": "11.3"
			}
		},
		"Results": [
			{
				"Target": "docker.io/library/nginx:1.21.6 (debian 11.3)",
				"Class": "os-pkgs",
				"Type": "debian",
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-2024-28085",
						"PkgName": "bsdutils",
						"InstalledVersion": "1:2.36.1-8+deb11u1",
						"FixedVersion": "2.36.1-8+deb11u2",
						"Severity": "MEDIUM"
					}
				]
			}
		]
	}`
	err = os.WriteFile(reportFile, []byte(reportContent), 0o600)
	require.NoError(t, err, "failed to create sample report file")

	// run copa patch with push flag
	targetImage := "localhost:5000/nginx:patched"
	patchCmd := exec.Command(
		copaPath,
		"patch",
		"--image", localImage,
		"--report", reportFile,
		"--push",
		"--tag", "patched",
		"-a="+buildkitAddr,
	)

	output, err := patchCmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("failed to patch and push image: %s", string(output)))

	// check it exists in registry by pulling it
	pullCmd := exec.Command("docker", "pull", targetImage)
	err = pullCmd.Run()
	require.NoError(t, err, "failed to pull patched image from registry")

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
