package nodejs

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeJSPatching(t *testing.T) {
	testCases := []struct {
		name                    string
		image                   string
		report                  string
		expectedPatches         int
		expectedVulnerabilities int
		shouldSucceed           bool
		expectedPackageVersions map[string]string
	}{
		{
			name:                    "vulnerable-node-app with npm vulnerabilities",
			image:                   "vulnerable-node-app:latest",
			report:                  "./testdata/vulnerable-node-app-report.json",
			expectedPatches:         7, // Number of Node.js vulnerabilities that should be patched
			expectedVulnerabilities: 0, // Expected remaining vulnerabilities in application packages
			shouldSucceed:           true,
			expectedPackageVersions: map[string]string{
				"ansi-regex": "3.0.1",
				"lodash":     "4.17.21",
				"minimist":   "1.2.8",
				"node-fetch": "2.7.0",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build test image if it doesn't exist
			if !imageExists(t, tc.image) {
				buildTestImage(t, tc.image)
			}

			// Run the patch operation
			output, err := runPatch(t, tc.image, tc.report)

			if tc.shouldSucceed {
				require.NoError(t, err, "Patch operation should succeed. Output: %s", string(output))

				// Verify that the expected number of Node.js patches were applied
				outputStr := string(output)
				assert.Contains(t, outputStr, fmt.Sprintf("Found %d Node.js vulnerabilities to patch", tc.expectedPatches),
					"Should find the expected number of Node.js vulnerabilities")
				assert.Contains(t, outputStr, fmt.Sprintf("Successfully applied %d Node.js package updates", tc.expectedPatches),
					"Should successfully apply the expected number of Node.js patches")

				// Verify patched image was created
				patchedImage := strings.Replace(tc.image, ":latest", ":patched", 1)
				assert.True(t, imageExists(t, patchedImage), "Patched image should exist")

				// Verify package versions were updated correctly
				if tc.expectedPackageVersions != nil {
					verifyPackageVersions(t, patchedImage, tc.expectedPackageVersions)
				}

				// Scan patched image to verify vulnerabilities were reduced
				if tc.expectedVulnerabilities >= 0 {
					verifyVulnerabilityReduction(t, patchedImage, tc.expectedVulnerabilities)
				}
			} else {
				assert.Error(t, err, "Patch operation should fail")
			}
		})
	}
}

func TestNodeJSPatchingEdgeCases(t *testing.T) {
	testCases := []struct {
		name          string
		image         string
		report        string
		shouldSucceed bool
		expectedError string
	}{
		{
			name:          "image without Node.js",
			image:         "alpine:3.14.0",
			report:        "./testdata/alpine-report.json",
			shouldSucceed: true, // Should succeed but skip Node.js patching
			expectedError: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := runPatch(t, tc.image, tc.report)

			if tc.shouldSucceed {
				assert.NoError(t, err, "Patch operation should succeed. Output: %s", string(output))
			} else {
				assert.Error(t, err, "Patch operation should fail")
				if tc.expectedError != "" {
					assert.Contains(t, string(output), tc.expectedError, "Should contain expected error message")
				}
			}
		})
	}
}

func runPatch(t *testing.T, image, report string) ([]byte, error) {
	args := []string{
		"patch",
		"-i=" + image,
		"-r=" + report,
		"-s=" + scannerPlugin,
		"-t=" + "patched",
	}
	if buildkitAddr != "" {
		args = append(args, "-a="+buildkitAddr)
	}

	t.Logf("Running copa patch with args: %v", args)

	if buildkitAddr != "" {
		args = append(args, "-a="+buildkitAddr)
	}

	//#nosec G204
	cmd := exec.Command(copaPath, args...)
	out, err := cmd.CombinedOutput()
	return out, err
}

func imageExists(t *testing.T, image string) bool {
	t.Helper()
	cmd := exec.Command("docker", "inspect", image)
	err := cmd.Run()
	return err == nil
}

func buildTestImage(t *testing.T, imageName string) {
	t.Helper()

	// Only build the vulnerable-node-app image, not arbitrary images
	if imageName != "vulnerable-node-app:latest" {
		t.Fatalf("buildTestImage only supports building vulnerable-node-app:latest, got: %s", imageName)
	}

	t.Logf("Building test image: %s", imageName)

	// Build the image from the testdata directory
	cmd := exec.Command("docker", "build", "-t", imageName, "./testdata/test-nodejs-app")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build test image %s: %v\nOutput: %s", imageName, err, string(output))
	}

	t.Logf("Successfully built test image: %s", imageName)
}

func verifyPackageVersions(t *testing.T, image string, expectedVersions map[string]string) {
	t.Helper()

	// Get package versions from the patched image
	cmd := exec.Command("docker", "run", "--rm", image, "sh", "-c", "cd /app && npm list --depth=0 --json")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Should be able to get package list from patched image")

	var npmList struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}

	err = json.Unmarshal(output, &npmList)
	require.NoError(t, err, "Should be able to parse npm list output")

	// Verify each expected package version
	for pkg, expectedVersion := range expectedVersions {
		dep, exists := npmList.Dependencies[pkg]
		assert.True(t, exists, "Package %s should exist in dependencies", pkg)
		if exists {
			assert.Equal(t, expectedVersion, dep.Version, "Package %s should have version %s", pkg, expectedVersion)
		}
	}
}

func verifyVulnerabilityReduction(t *testing.T, image string, expectedVulns int) {
	t.Helper()

	// Run Trivy scan on patched image
	cmd := exec.Command("trivy", "image", "--format", "table", image)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Trivy scan output: %s", string(output))
		require.NoError(t, err, "Should be able to scan patched image with Trivy")
	}

	// For now, just check that the command succeeds and that there are fewer vulnerabilities
	// A more sophisticated check would parse the table output or use JSON format properly
	outputStr := string(output)

	// Count lines that contain "HIGH" or "CRITICAL" vulnerabilities in app packages
	appVulnLines := 0
	for _, line := range strings.Split(outputStr, "\n") {
		if strings.Contains(line, "app/") && (strings.Contains(line, "HIGH") || strings.Contains(line, "CRITICAL")) {
			appVulnLines++
		}
	}

	assert.LessOrEqual(t, appVulnLines, expectedVulns,
		"Patched image should have at most %d HIGH/CRITICAL vulnerabilities in application packages", expectedVulns)
}
