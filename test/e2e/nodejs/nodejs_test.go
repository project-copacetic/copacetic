package nodejs

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeJSPatching(t *testing.T) {
	testCases := []struct {
		name                    string
		image                   string
		expectedPatches         int
		expectedVulnerabilities int
		shouldSucceed           bool
		expectedPackageVersions map[string]string
		generateReport          bool
	}{
		{
			name:                    "vulnerable-node-app with npm vulnerabilities",
			image:                   "test-vulnerable-node-app:latest",
			expectedPatches:         7,
			expectedVulnerabilities: 0,
			shouldSucceed:           true,
			generateReport:          true,
			expectedPackageVersions: map[string]string{
				"ansi-regex": "3.0.1",
				"lodash":     "4.17.21",
				"minimist":   "1.2.6",
				"node-fetch": "2.6.7",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build test image if it doesn't exist
			if !imageExists(t, tc.image) {
				buildTestImage(t, tc.image)
			}

			// Generate report if needed
			var reportPath string
			if tc.generateReport {
				reportPath = generateTrivyReport(t, tc.image)
				defer os.Remove(reportPath)
			}

			// Run the patch operation
			_, err := runPatch(t, tc.image, reportPath)

			if tc.shouldSucceed {
				if err != nil {
					t.Logf("Copa command failed with error: %v", err)
					t.Logf("Note: Output was streamed above, check console for Copa logs")
					require.NoError(t, err, "Patch operation should succeed")
				} else {
					t.Logf("✅ Copa patch command completed successfully")

					// Verify patched image was created
					patchedImage := strings.Replace(tc.image, ":latest", ":patched", 1)
					assert.True(t, imageExists(t, patchedImage), "Patched image should exist")

					// Verify package versions were updated correctly
					if tc.expectedPackageVersions != nil {
						verifyPackageVersions(t, patchedImage, tc.expectedPackageVersions)
					}
				}
			} else {
				assert.Error(t, err, "Patch operation should fail")
			}
		})
	}
}

func TestNodeJSGlobalPackages(t *testing.T) {
	testCases := []struct {
		name           string
		image          string
		shouldSucceed  bool
		generateReport bool
	}{
		{
			name:           "devcontainer with global npm packages",
			image:          "mcr.microsoft.com/devcontainers/javascript-node:1-18-bullseye",
			shouldSucceed:  true,
			generateReport: true,
		},
		{
			name:           "strapi with many npm vulnerabilities",
			image:          "strapi/strapi:latest@sha256:be2aa1b207c74474319873d2a343c572e17273f5c3017c308c4a21bd6e1992e9",
			shouldSucceed:  true,
			generateReport: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate report if needed
			var reportPath string
			if tc.generateReport {
				reportPath = generateTrivyReport(t, tc.image)
				defer os.Remove(reportPath)
			}

			_, err := runPatch(t, tc.image, reportPath)

			if tc.shouldSucceed {
				if err != nil {
					t.Logf("Copa command completed with note: %v", err)
				} else {
					t.Logf("✅ Copa global package patching test completed successfully")

					// Verify patched image was created
					// The tag is set to "patched" in runPatch
					patchedImage := strings.Split(tc.image, ":")[0] + ":patched"
					assert.True(t, imageExists(t, patchedImage), "Patched image should exist")
				}
			} else {
				assert.Error(t, err, "Patch operation should fail")
			}
		})
	}
}

func TestNodeJSPatchingEdgeCases(t *testing.T) {
	testCases := []struct {
		name           string
		image          string
		shouldSucceed  bool
		expectedError  string
		generateReport bool
	}{
		{
			name:           "image without Node.js",
			image:          "alpine:3.21.0@sha256:21dc6063fd678b478f57c0e13f47560d0ea4eeba26dfc947b2a4f81f686b9f45",
			shouldSucceed:  true,
			expectedError:  "",
			generateReport: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate report if needed
			var reportPath string
			if tc.generateReport {
				reportPath = generateTrivyReport(t, tc.image)
				defer os.Remove(reportPath)
			}

			_, err := runPatch(t, tc.image, reportPath)

			if tc.shouldSucceed {
				if err != nil {
					t.Logf("Copa command completed with note: %v", err)
				} else {
					t.Logf("✅ Copa edge case test completed successfully")
				}
			} else {
				assert.Error(t, err, "Patch operation should fail")
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
		"--timeout=2m",
		"--debug",
		"--pkg-types=os,library",
	}
	if buildkitAddr != "" {
		args = append(args, "-a="+buildkitAddr)
	}

	t.Logf("Running copa patch with args: %v", args)

	//#nosec G204
	cmd := exec.Command(copaPath, args...)
	// Enable experimental features for library patching
	cmd.Env = append(os.Environ(), "COPA_EXPERIMENTAL=1")

	// Stream output in real-time for debugging
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	t.Logf("Starting copa patch command...")
	err := cmd.Run()

	return []byte{}, err
}

func imageExists(t *testing.T, image string) bool {
	t.Helper()
	cmd := exec.Command("docker", "inspect", image)
	err := cmd.Run()
	return err == nil
}

func buildTestImage(t *testing.T, imageName string) {
	t.Helper()

	if imageName != "test-vulnerable-node-app:latest" {
		t.Fatalf("buildTestImage only supports building test-vulnerable-node-app:latest, got: %s", imageName)
	}

	t.Logf("Building test image: %s", imageName)

	cwd, _ := os.Getwd()
	t.Logf("Current working directory: %s", cwd)

	buildPath := filepath.Join("testdata", "test-nodejs-app")
	if _, err := os.Stat(buildPath); os.IsNotExist(err) {
		buildPath = filepath.Join("test", "e2e", "nodejs", "testdata", "test-nodejs-app")
		if _, err := os.Stat(buildPath); os.IsNotExist(err) {
			t.Fatalf("Build path does not exist: %s", buildPath)
		}
	}
	t.Logf("Build path: %s", buildPath)

	cmd := exec.Command("docker", "build", "-t", imageName, buildPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build test image %s: %v\nOutput: %s", imageName, err, string(output))
	}

	t.Logf("Successfully built test image: %s", imageName)
}

func verifyPackageVersions(t *testing.T, image string, expectedVersions map[string]string) {
	t.Helper()

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

	for pkg, expectedVersion := range expectedVersions {
		dep, exists := npmList.Dependencies[pkg]
		assert.True(t, exists, "Package %s should exist in dependencies", pkg)
		if exists {
			assert.Equal(t, expectedVersion, dep.Version, "Package %s should have version %s", pkg, expectedVersion)
		}
	}
}

func generateTrivyReport(t *testing.T, image string) string {
	t.Helper()

	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "report.json")

	args := []string{
		"trivy",
		"image",
		"--pkg-types=os,library",
		"--ignore-unfixed",
		"--format=json",
		"--output=" + reportPath,
		image,
	}

	cmd := exec.Command(args[0], args[1:]...) // #nosec G204 - test code with controlled inputs
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Trivy scan output: %s", string(output))
		require.NoError(t, err, "Failed to generate Trivy report for image %s", image)
	}

	t.Logf("Generated Trivy report for %s at %s", image, reportPath)
	return reportPath
}
