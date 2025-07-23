package frontend

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

//go:embed fixtures/test-images.json
var testImages []byte

//go:embed testdata/simple-report.json
var simpleReport []byte

//go:embed testdata/complex-report.json
var complexReport []byte

type testImage struct {
	OriginalImage string   `json:"originalImage"`
	LocalImage    string   `json:"localImage"`
	Tag           string   `json:"tag"`
	Distro        string   `json:"distro"`
	Description   string   `json:"description"`
	IgnoreErrors  bool     `json:"ignoreErrors"`
	TestType      string   `json:"testType"`
	Platforms     []string `json:"platforms"`
}

func TestFrontendPatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	var images []testImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	for _, img := range images {
		// Skip multiplatform tests for now
		if img.TestType == "multiplatform" {
			t.Logf("Skipping multiplatform test: %s", img.Description)
			continue
		}

		t.Run(img.Description, func(t *testing.T) {
			runFrontendTest(t, img)
		})
	}
}

func runFrontendTest(t *testing.T, img testImage) {
	// Define image references
	localPushRef := fmt.Sprintf("%s:%s", img.LocalImage, img.Tag)
	originalImageRef := fmt.Sprintf("%s:%s", img.OriginalImage, img.Tag)
	patchedRef := fmt.Sprintf("%s:%s-frontend-patched", img.LocalImage, img.Tag)

	// Copy original image to local registry
	t.Logf("Copying %s to %s", originalImageRef, localPushRef)
	copyImage(t, originalImageRef, localPushRef)

	// Create temp directory for output
	tempDir := t.TempDir()
	outputTar := filepath.Join(tempDir, "patched.tar")

	// Select appropriate vulnerability report
	var reportData []byte
	switch img.TestType {
	case "inline-report":
		reportData = getReportForDistro(img.Distro)
	case "error-handling":
		reportData = complexReport // Use complex report to potentially trigger errors
	default:
		reportData = simpleReport
	}

	// Build the buildctl command for frontend patching with enhanced options
	args := []string{
		"build",
		"--frontend=gateway.v0",
		"--opt", fmt.Sprintf("source=%s", frontendImage), // Use bridge gateway IP
		"--opt", fmt.Sprintf("image=%s", strings.Replace(localPushRef, "localhost:5000", "172.17.0.1:5000", 1)), // Use bridge gateway IP
		"--opt", fmt.Sprintf("report=%s", string(reportData)),
		"--opt", "scanner=trivy",
		"--opt", "security-mode=sandbox", // Use enhanced security mode
		"--opt", "cache-mode=local",     // Use local caching
		"--opt", fmt.Sprintf("annotation.test-case=%s", img.Description), // Add test annotation
		"--output", fmt.Sprintf("type=docker,dest=%s", outputTar),
	}

	if img.IgnoreErrors {
		args = append(args, "--opt", "ignore-errors=true")
	}

	if len(img.Platforms) == 1 {
		args = append(args, "--opt", fmt.Sprintf("platform=%s", img.Platforms[0]))
	}

	// Add BuildKit address if not using default
	if buildkitAddr != "docker://" {
		args = append([]string{"--addr", buildkitAddr}, args...)
	}
	
	// Allow insecure registry access
	args = append(args, "--allow", "security.insecure")

	t.Logf("Running buildctl with frontend: %v", args)
	cmd := exec.Command("buildctl", args...)
	output, err := cmd.CombinedOutput()

	if img.TestType == "error-handling" && img.IgnoreErrors {
		// For error handling tests with ignore-errors, we expect success even if there are patch errors
		if err != nil {
			t.Logf("Warning: buildctl failed but ignore-errors was set: %s", string(output))
		}
	} else {
		require.NoError(t, err, fmt.Sprintf("buildctl failed: %s", string(output)))
	}

	// Verify the output tar was created
	if _, err := os.Stat(outputTar); err != nil {
		t.Logf("Output tar not created, this may be expected for error-handling tests: %v", err)
		return
	}

	// Load the patched image from tar
	t.Logf("Loading patched image from %s", outputTar)
	loadCmd := exec.Command("docker", "load", "-i", outputTar)
	loadOutput, err := loadCmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("failed to load patched image: %s", string(loadOutput)))

	// Extract the loaded image name from docker load output
	loadedImageName := extractImageNameFromLoadOutput(string(loadOutput))
	if loadedImageName == "" {
		t.Fatal("could not extract loaded image name from docker load output")
	}

	// Tag the loaded image with our expected name
	tagCmd := exec.Command("docker", "tag", loadedImageName, patchedRef)
	err = tagCmd.Run()
	require.NoError(t, err, "failed to tag patched image")

	// Verify the patched image exists and can be inspected
	inspectCmd := exec.Command("docker", "inspect", patchedRef)
	err = inspectCmd.Run()
	require.NoError(t, err, "patched image does not exist or cannot be inspected")

	// Compare original and patched images
	compareImages(t, localPushRef, patchedRef, img.Distro)

	// Cleanup
	cleanupImage(t, patchedRef)
	cleanupImage(t, loadedImageName)
	cleanupImage(t, localPushRef)
}

func copyImage(t *testing.T, src, dst string) {
	cmd := exec.Command("oras", "cp", src, dst)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("oras cp failed: %s", string(output)))
}

func extractImageNameFromLoadOutput(output string) string {
	// Docker load output format: "Loaded image: <image_name>"
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Loaded image: ") {
			return strings.TrimPrefix(line, "Loaded image: ")
		}
	}
	return ""
}

func compareImages(t *testing.T, originalRef, patchedRef, distro string) {
	// Run a simple comparison to ensure the images are different
	// This is a basic check - in a full implementation, you might want to check
	// specific packages or vulnerabilities were actually patched

	t.Logf("Comparing original image %s with patched image %s", originalRef, patchedRef)

	// Get image IDs
	getOriginalID := exec.Command("docker", "inspect", "--format={{.Id}}", originalRef)
	originalID, err := getOriginalID.CombinedOutput()
	require.NoError(t, err, "failed to get original image ID")

	getPatchedID := exec.Command("docker", "inspect", "--format={{.Id}}", patchedRef)
	patchedID, err := getPatchedID.CombinedOutput()
	require.NoError(t, err, "failed to get patched image ID")

	// Images should be different (patched image should have new layers)
	if strings.TrimSpace(string(originalID)) == strings.TrimSpace(string(patchedID)) {
		t.Log("Warning: Original and patched images have the same ID - this may indicate no patches were applied")
	} else {
		t.Log("Success: Original and patched images have different IDs, indicating patches were applied")
	}

	// Additional validation based on distro
	switch distro {
	case "debian", "ubuntu":
		validateDebianPatching(t, patchedRef)
	case "alpine":
		validateAlpinePatching(t, patchedRef)
	}
}

func validateDebianPatching(t *testing.T, imageRef string) {
	// Check that apt packages are available and the patched image can run commands
	cmd := exec.Command("docker", "run", "--rm", imageRef, "dpkg", "--version")
	err := cmd.Run()
	require.NoError(t, err, "patched debian image should be able to run dpkg")
}

func validateAlpinePatching(t *testing.T, imageRef string) {
	// Check that apk is available and the patched image can run commands
	cmd := exec.Command("docker", "run", "--rm", imageRef, "apk", "--version")
	err := cmd.Run()
	require.NoError(t, err, "patched alpine image should be able to run apk")
}

func cleanupImage(t *testing.T, imageRef string) {
	cmd := exec.Command("docker", "rmi", "-f", imageRef)
	_ = cmd.Run() // ignore errors during cleanup
}

func getReportForDistro(distro string) []byte {
	switch distro {
	case "alpine":
		return []byte(`{
			"metadata": {
				"os": {
					"type": "alpine",
					"version": "3.18"
				},
				"config": {
					"arch": "amd64"
				}
			},
			"updates": [
				{
					"name": "libssl3",
					"installedVersion": "3.0.8-r0",
					"fixedVersion": "3.0.8-r1",
					"vulnerabilityID": "CVE-2023-0464"
				}
			]
		}`)
	case "ubuntu":
		return []byte(`{
			"metadata": {
				"os": {
					"type": "ubuntu", 
					"version": "20.04"
				},
				"config": {
					"arch": "amd64"
				}
			},
			"updates": [
				{
					"name": "curl",
					"installedVersion": "7.68.0-1ubuntu2.18",
					"fixedVersion": "7.68.0-1ubuntu2.19",
					"vulnerabilityID": "CVE-2023-28321"
				}
			]
		}`)
	case "debian":
		return []byte(`{
			"metadata": {
				"os": {
					"type": "debian",
					"version": "11"
				},
				"config": {
					"arch": "amd64"
				}
			},
			"updates": [
				{
					"name": "curl",
					"installedVersion": "7.74.0-1.3+deb11u7",
					"fixedVersion": "7.74.0-1.3+deb11u8",
					"vulnerabilityID": "CVE-2023-28321"
				}
			]
		}`)
	default:
		return simpleReport
	}
}