package frontend

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

// ensureBuildxBuilder creates a BuildKit builder with insecure registry support for testing.
func ensureBuildxBuilder(t *testing.T) string {
	builderName := "copa-frontend-test-builder"

	// Remove existing builder if it exists
	_ = exec.Command("docker", "buildx", "rm", builderName).Run()

	// Create buildkitd.toml config for insecure registries
	configContent := `[registry."localhost:5000"]
  http = true
  insecure = true

[registry."172.17.0.1:5000"] 
  http = true
  insecure = true`

	configFile := "/tmp/buildkitd-frontend-test.toml"
	err := os.WriteFile(configFile, []byte(configContent), 0o600)
	if err != nil {
		t.Fatalf("Failed to create buildkitd config: %v", err)
	}

	// Create new builder with insecure registry config
	cmd := exec.Command("docker", "buildx", "create", "--name", builderName,
		"--driver", "docker-container",
		"--driver-opt", "network=host",
		"--config", configFile,
		"--buildkitd-flags", "--allow-insecure-entitlement=network.host --allow-insecure-entitlement=security.insecure")

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to create buildx builder: %v\nOutput: %s", err, output)
	}

	// Bootstrap the builder
	cmd = exec.Command("docker", "buildx", "inspect", "--bootstrap", builderName)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to bootstrap buildx builder: %v\nOutput: %s", err, output)
	}

	return fmt.Sprintf("docker-container://buildx_buildkit_%s0", builderName)
}

func TestFrontendPatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// Check if buildctl is available
	if _, err := exec.LookPath("buildctl"); err != nil {
		t.Skip("skipping frontend tests; buildctl binary not found in path")
	}

	// Check if trivy is available
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("skipping frontend tests; trivy binary not found in path")
	}

	// Setup local registry for testing
	ctx := context.Background()
	setupLocalRegistry(ctx, t)
	defer stopLocalRegistry(t)

	// Build the frontend image
	buildFrontendImage(t)

	// Test cases - now using actual Trivy scans
	testCases := []struct {
		name       string
		baseImage  string
		localImage string
	}{
		{
			name:       "nginx-debian",
			baseImage:  "docker.io/library/nginx:1.21.6",
			localImage: "localhost:5000/nginx:1.21.6",
		},
		{
			name:       "alpine",
			baseImage:  "docker.io/library/alpine:3.18",
			localImage: "localhost:5000/alpine:3.18",
		},
		{
			name:       "ubuntu",
			baseImage:  "docker.io/library/ubuntu:20.04",
			localImage: "localhost:5000/ubuntu:20.04",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runFrontendTest(t, tc.baseImage, tc.localImage)
		})
	}
}

func runFrontendTest(t *testing.T, baseImage, localImage string) {
	// Copy image to local registry
	t.Logf("Copying %s to %s", baseImage, localImage)
	copyCmd := exec.Command("oras", "cp", baseImage, localImage)
	output, err := copyCmd.CombinedOutput()
	require.NoErrorf(t, err, "oras cp failed:\n%s", string(output))
	defer removeLocalImage(t, localImage)

	// Create temp directory and output file
	tempDir, err := os.MkdirTemp("", "copa-frontend-test-*")
	require.NoError(t, err, "failed to create temp directory")
	defer os.RemoveAll(tempDir)

	// Run Trivy scan to generate actual vulnerability report
	reportFile := filepath.Join(tempDir, "report.json")
	t.Logf("Scanning %s with Trivy to generate report", localImage)

	trivyCmd := exec.Command("trivy", "image",
		"--format", "json",
		"--output", reportFile,
		"--quiet",
		"--no-progress",
		"--insecure", // Allow scanning images from insecure registries
		localImage)

	trivyOutput, err := trivyCmd.CombinedOutput()
	if err != nil {
		t.Logf("Trivy scan output: %s", string(trivyOutput))
		require.NoError(t, err, "failed to run trivy scan")
	}

	// Verify the report file was created
	if _, err := os.Stat(reportFile); err != nil {
		t.Fatalf("Trivy report file was not created: %v", err)
	}

	t.Logf("Trivy report generated at: %s", reportFile)

	// Create a dummy Dockerfile for context compatibility
	dockerfilePath := filepath.Join(tempDir, "Dockerfile")
	err = os.WriteFile(dockerfilePath, []byte("FROM scratch\n"), 0o600)
	require.NoError(t, err, "failed to create dummy Dockerfile")

	outputTar := filepath.Join(tempDir, "patched.tar")

	// Build the buildctl command for frontend patching
	frontendImageRef := strings.Replace(frontendImage, "localhost:5000", "172.17.0.1:5000", 1) // Use bridge gateway IP
	localImageRef := strings.Replace(localImage, "localhost:5000", "172.17.0.1:5000", 1)       // Use bridge gateway IP

	args := []string{
		"build",
		"--frontend=gateway.v0",
		"--opt", fmt.Sprintf("source=%s", frontendImageRef),
		"--opt", fmt.Sprintf("image=%s", localImageRef),
		"--opt", fmt.Sprintf("report=%s", reportFile), // Pass report file path - consistent with patch command
		"--opt", "scanner=trivy",
		"--opt", "security-mode=sandbox",
		"--opt", "cache-mode=local",
		"--output", "type=docker,dest=" + outputTar,
		"--opt", "platform=linux/amd64",
	}

	// Handle buildx:// address - this buildctl version doesn't support buildx://
	actualAddr := buildkitAddr
	if buildkitAddr == "buildx://" {
		// This buildctl version doesn't support buildx://, so we create our own builder
		actualAddr = ensureBuildxBuilder(t)
		t.Logf("buildx:// not supported by this buildctl version, using %s", actualAddr)
	}

	args = append([]string{"--addr", actualAddr}, args...)

	// Allow insecure registry access
	args = append(args, "--allow", "security.insecure")

	t.Logf("Running buildctl with frontend using report file: %s", reportFile)
	t.Logf("BuildKit command: %v", args)
	cmd := exec.Command("buildctl", args...)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("buildctl failed: %s", string(output)))

	// Verify the output tar was created
	if _, err := os.Stat(outputTar); err != nil {
		t.Fatalf("Output tar was not created: %v", err)
	}

	// Load the patched image
	t.Logf("Loading patched image from %s", outputTar)
	loadCmd := exec.Command("docker", "load", "-i", outputTar)
	loadOutput, err := loadCmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("failed to load patched image: %s", string(loadOutput)))

	// Extract image name from docker load output
	loadOutputStr := string(loadOutput)
	t.Logf("Docker load output: %s", loadOutputStr)

	// The load output typically contains "Loaded image: <image-name>" or "Loaded image ID: <id>"
	// We'll accept success if the load command succeeded
	if strings.Contains(loadOutputStr, "Loaded image") {
		t.Logf("Successfully loaded patched image")
	} else {
		t.Logf("Image loaded but couldn't parse image name from output")
	}
}

func setupLocalRegistry(ctx context.Context, t *testing.T) {
	// Check if registry is already running and clean it up
	dockerCli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err, "failed to create docker client")

	containers, err := dockerCli.ContainerList(ctx, container_types.ListOptions{All: true})
	require.NoError(t, err, "failed to list containers")

	for i := range containers {
		container := &containers[i]
		for _, name := range container.Names {
			if name == "/registry-frontend-test" {
				// Remove existing registry
				err := dockerCli.ContainerRemove(ctx, container.ID, container_types.RemoveOptions{Force: true})
				require.NoError(t, err, "failed to remove existing registry container")
				break
			}
		}
	}

	// Start registry container
	t.Log("Starting local Docker registry for frontend tests...")
	cmd := exec.Command("docker", "run", "-d", "-p", "5000:5000", "--name", "registry-frontend-test", "registry:2")
	err = cmd.Run()
	require.NoError(t, err, "failed to start registry container")

	// Wait for registry to be ready
	time.Sleep(3 * time.Second)
	t.Log("Local registry is ready at localhost:5000")
}

func stopLocalRegistry(t *testing.T) {
	t.Log("Stopping local Docker registry...")
	cmd := exec.Command("docker", "rm", "-f", "registry-frontend-test")
	_ = cmd.Run() // ignore errors during cleanup
}

func buildFrontendImage(t *testing.T) {
	t.Logf("Building Copa frontend image: %s", frontendImage)

	// First build the frontend binary locally to avoid Docker disk space issues
	t.Log("Building frontend binary locally...")
	buildCmd := exec.Command("go", "build", "-ldflags", "-s -w", "-o", "copa-frontend", "./cmd/frontend")
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")

	// Set working directory to project root (3 levels up from test/e2e/frontend)
	wd, _ := os.Getwd()
	projectRoot := filepath.Join(wd, "..", "..", "..")
	buildCmd.Dir = projectRoot

	output, err := buildCmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("failed to build frontend binary: %v\nOutput: %s", err, string(output)))

	// Create a simple Dockerfile for the frontend image
	dockerfileContent := `FROM alpine:3.18
RUN apk add --no-cache ca-certificates busybox
COPY copa-frontend /usr/bin/copa-frontend
RUN chmod +x /usr/bin/copa-frontend
ENTRYPOINT ["/usr/bin/copa-frontend"]`

	dockerfilePath := filepath.Join(projectRoot, "frontend-simple.Dockerfile")
	binaryPath := filepath.Join(projectRoot, "copa-frontend")

	err = os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0o600)
	require.NoError(t, err, "failed to create simple Dockerfile")
	defer os.Remove(dockerfilePath)
	defer os.Remove(binaryPath)

	// Build the Docker image - use buildx with --load if available
	var cmd *exec.Cmd
	if _, err := exec.LookPath("docker"); err == nil {
		// Check if buildx is available
		if checkCmd := exec.Command("docker", "buildx", "version"); checkCmd.Run() == nil {
			cmd = exec.Command("docker", "buildx", "build", "--load", "-f", "frontend-simple.Dockerfile", "-t", frontendImage, ".")
		} else {
			cmd = exec.Command("docker", "build", "-f", "frontend-simple.Dockerfile", "-t", frontendImage, ".")
		}
	}
	cmd.Dir = projectRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	require.NoError(t, err, "failed to build frontend image")
	t.Logf("Frontend image built successfully: %s", frontendImage)

	// Push the frontend image to the local registry so BuildKit can access it
	// Use localhost for pushing (from host) but bridge gateway for BuildKit access
	localPushImage := "localhost:5000/copa-frontend:test"
	buildkitAccessImage := "172.17.0.1:5000/copa-frontend:test"

	tagCmd := exec.Command("docker", "tag", frontendImage, localPushImage)
	err = tagCmd.Run()
	require.NoError(t, err, "failed to tag frontend image")

	pushCmd := exec.Command("docker", "push", localPushImage)
	pushOutput, err := pushCmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("failed to push frontend image: %v\nOutput: %s", err, string(pushOutput)))

	// Update the frontendImage variable to use the bridge gateway IP for BuildKit access
	frontendImage = buildkitAccessImage
	t.Logf("Frontend image pushed to local registry and accessible via: %s", frontendImage)
}

func removeLocalImage(_ *testing.T, image string) {
	cmd := exec.Command("docker", "rmi", "-f", image)
	_ = cmd.Run() // ignore errors during cleanup
}
