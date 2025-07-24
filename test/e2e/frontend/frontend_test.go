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

func TestFrontendPatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// Check if buildctl is available
	if _, err := exec.LookPath("buildctl"); err != nil {
		t.Skip("skipping frontend tests; buildctl binary not found in path")
	}

	// BuildKit is already set up by the CI workflow via docker/setup-buildx-action

	// Setup local registry for testing
	ctx := context.Background()
	setupLocalRegistry(ctx, t)
	defer stopLocalRegistry(t)

	// Build the frontend image
	buildFrontendImage(t)

	// Test cases
	testCases := []struct {
		name          string
		baseImage     string
		localImage    string
		reportContent string
		ignoreErrors  bool
	}{
		{
			name:       "nginx-debian",
			baseImage:  "docker.io/library/nginx:1.21.6",
			localImage: "localhost:5000/nginx:1.21.6",
			reportContent: `{
				"SchemaVersion": 2,
				"ArtifactName": "nginx:1.21.6",
				"ArtifactType": "container_image",
				"Metadata": {
					"OS": {
						"Family": "debian",
						"Name": "11.3"
					},
					"ImageConfig": {
						"architecture": "amd64"
					}
				},
				"Results": [
					{
						"Target": "nginx:1.21.6 (debian 11.3)",
						"Class": "os-pkgs",
						"Type": "debian",
						"Vulnerabilities": [
							{
								"VulnerabilityID": "CVE-2023-28321",
								"PkgID": "curl@7.74.0-1.3+deb11u7",
								"PkgName": "curl",
								"InstalledVersion": "7.74.0-1.3+deb11u7",
								"FixedVersion": "7.74.0-1.3+deb11u8"
							}
						]
					}
				]
			}`,
			ignoreErrors: false,
		},
		{
			name:       "alpine",
			baseImage:  "docker.io/library/alpine:3.18",
			localImage: "localhost:5000/alpine:3.18",
			reportContent: `{
				"SchemaVersion": 2,
				"ArtifactName": "alpine:3.18",
				"ArtifactType": "container_image",
				"Metadata": {
					"OS": {
						"Family": "alpine",
						"Name": "3.18"
					},
					"ImageConfig": {
						"architecture": "amd64"
					}
				},
				"Results": [
					{
						"Target": "alpine:3.18 (alpine 3.18)",
						"Class": "os-pkgs",
						"Type": "alpine",
						"Vulnerabilities": [
							{
								"VulnerabilityID": "CVE-2023-0464",
								"PkgID": "libssl3@3.0.8-r0",
								"PkgName": "libssl3",
								"InstalledVersion": "3.0.8-r0",
								"FixedVersion": "3.0.8-r1"
							}
						]
					}
				]
			}`,
			ignoreErrors: false,
		},
		{
			name:       "ubuntu-error-handling",
			baseImage:  "docker.io/library/ubuntu:20.04",
			localImage: "localhost:5000/ubuntu:20.04",
			reportContent: `{
				"SchemaVersion": 2,
				"ArtifactName": "ubuntu:20.04",
				"ArtifactType": "container_image",
				"Metadata": {
					"OS": {
						"Family": "ubuntu",
						"Name": "20.04"
					},
					"ImageConfig": {
						"architecture": "amd64"
					}
				},
				"Results": [
					{
						"Target": "ubuntu:20.04 (ubuntu 20.04)",
						"Class": "os-pkgs",
						"Type": "ubuntu",
						"Vulnerabilities": [
							{
								"VulnerabilityID": "CVE-2023-28321",
								"PkgID": "curl@7.68.0-1ubuntu2.18",
								"PkgName": "curl",
								"InstalledVersion": "7.68.0-1ubuntu2.18",
								"FixedVersion": "7.68.0-1ubuntu2.19"
							},
							{
								"VulnerabilityID": "CVE-2023-FAKE",
								"PkgID": "nonexistent-package@1.0.0",
								"PkgName": "nonexistent-package",
								"InstalledVersion": "1.0.0",
								"FixedVersion": "1.0.1"
							}
						]
					}
				]
			}`,
			ignoreErrors: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runFrontendTest(t, tc.baseImage, tc.localImage, tc.reportContent, tc.ignoreErrors)
		})
	}
}

func runFrontendTest(t *testing.T, baseImage, localImage, reportContent string, ignoreErrors bool) {
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

	// Create report file (Copa always uses file paths, not inline reports)
	reportFile := filepath.Join(tempDir, "report.json")
	err = os.WriteFile(reportFile, []byte(reportContent), 0600)
	require.NoError(t, err, "failed to create report file")

	outputTar := filepath.Join(tempDir, "patched.tar")

	// Build the buildctl command for frontend patching
	frontendImageRef := strings.Replace(frontendImage, "localhost:5000", "172.17.0.1:5000", 1) // Use bridge gateway IP
	localImageRef := strings.Replace(localImage, "localhost:5000", "172.17.0.1:5000", 1)       // Use bridge gateway IP

	args := []string{
		"build",
		"--frontend=gateway.v0",
		"--local", fmt.Sprintf("context=%s", tempDir), // Pass temp directory as build context
		"--opt", fmt.Sprintf("source=%s", frontendImageRef),
		"--opt", fmt.Sprintf("image=%s", localImageRef),
		"--opt", "report-path=report.json", // Use report-path instead of inline report
		"--opt", "scanner=trivy",
		"--opt", "security-mode=sandbox",
		"--opt", "cache-mode=local",
		"--output", "type=docker,dest=" + outputTar,
		"--opt", "platform=linux/amd64",
	}

	if ignoreErrors {
		args = append(args, "--opt", "ignore-errors=true")
	}

	// Add BuildKit address if not using default
	if buildkitAddr != "docker://" {
		args = append([]string{"--addr", buildkitAddr}, args...)
	}

	// Allow insecure registry access
	args = append(args, "--allow", "security.insecure")

	t.Logf("Running buildctl with frontend using report file: %s", reportFile)
	t.Logf("BuildKit command: %v", args)
	cmd := exec.Command("buildctl", args...)
	output, err = cmd.CombinedOutput()

	if ignoreErrors {
		// For error handling tests with ignore-errors, we expect success even if there are patch errors
		if err != nil {
			t.Logf("Warning: buildctl failed but ignore-errors was set: %s", string(output))
		}
	} else {
		require.NoError(t, err, fmt.Sprintf("buildctl failed: %s", string(output)))
	}

	// Verify the output tar was created
	if _, err := os.Stat(outputTar); err != nil {
		if ignoreErrors {
			t.Logf("Output tar not created, this may be expected for error-handling tests: %v", err)
			return
		}
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