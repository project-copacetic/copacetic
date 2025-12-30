package golang

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

// TestGolanggoBinaryPatching tests end-to-end Go binary patching using heuristic detection.
func TestGoBinaryPatching(t *testing.T) {
	if os.Getenv("COPA_TEST_SKIP_GOLANG") == "1" {
		t.Skip("Skipping Go binary patching test (COPA_TEST_SKIP_GOLANG=1)")
	}

	// Set experimental flag
	t.Setenv("COPA_EXPERIMENTAL", "1")

	testCases := []struct {
		name        string
		image       string
		description string
		expectFix   bool // whether we expect vulnerabilities to be fixed
	}{
		{
			name:        "CoreDNS with dependency vulnerability",
			image:       "docker.io/coredns/coredns:latest",
			description: "CoreDNS image with github.com/expr-lang/expr vulnerability",
			expectFix:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create temp directory for test artifacts
			tempDir, err := os.MkdirTemp("", "copa-golang-test-*")
			require.NoError(t, err, "Failed to create temp dir")
			defer os.RemoveAll(tempDir)

			// Scan original image
			originalScanFile := filepath.Join(tempDir, "original-scan.json")
			t.Logf("Scanning original image: %s", tc.image)
			scanCmd := exec.Command("trivy", "image", "--format", "json",
				"--output", originalScanFile, tc.image)
			output, err := scanCmd.CombinedOutput()
			require.NoError(t, err, "Trivy scan failed: %s", string(output))

			// Parse original scan to get Go binary vulnerabilities
			originalVulns, err := getGoBinaryVulns(originalScanFile)
			require.NoError(t, err, "Failed to parse original scan")
			require.NotEmpty(t, originalVulns, "No Go binary vulnerabilities found in original image")
			t.Logf("Found %d Go binary vulnerabilities in original image", len(originalVulns))

			// Patch the image
			// Use simple tag like "coredns-patched" to avoid image naming issues
			imageParts := strings.Split(tc.image, "/")
			imageName := imageParts[len(imageParts)-1] // get last part (e.g., "coredns:latest")
			imageName = strings.Split(imageName, ":")[0] // remove tag (e.g., "coredns")
			patchedTag := imageName + ":patched"
			patchedOutputFile := filepath.Join(tempDir, "patched.tar")

			t.Logf("Patching image...")
			copaPath := os.Getenv("COPA_BINARY")
			if copaPath == "" {
				// Try to find copa in common locations
				for _, path := range []string{
					"../../../dist/linux_amd64/release/copa",
					"/tmp/copa-test",
					"./copa",
				} {
					if _, err := os.Stat(path); err == nil {
						copaPath = path
						break
					}
				}
			}
			require.NotEmpty(t, copaPath, "Copa binary not found. Set COPA_BINARY or build first")

			patchCmd := exec.Command(copaPath, "patch",
				"--image", tc.image,
				"--report", originalScanFile,
				"--output", patchedOutputFile,
				"--tag", patchedTag,
				"--timeout", "15m",
				"--enable-go-binary-rebuild",
				"--pkg-types", "os,library")
			patchOutput, err := patchCmd.CombinedOutput()
			if err != nil {
				t.Logf("Copa patch output:\n%s", string(patchOutput))
			}
			require.NoError(t, err, "Copa patch failed")

			// Verify patched image was created
			checkImageCmd := exec.Command("docker", "images", patchedTag, "--format", "{{.Repository}}:{{.Tag}}")
			imageOutput, err := checkImageCmd.Output()
			require.NoError(t, err, "Failed to check for patched image")
			assert.Contains(t, string(imageOutput), patchedTag, "Patched image not found")

			if tc.expectFix {
				// Scan patched image
				patchedScanFile := filepath.Join(tempDir, "patched-scan.json")
				t.Logf("Scanning patched image: %s", patchedTag)
				scanPatchedCmd := exec.Command("trivy", "image", "--format", "json",
					"--output", patchedScanFile, patchedTag)
				scanOutput, err := scanPatchedCmd.CombinedOutput()
				require.NoError(t, err, "Trivy scan of patched image failed: %s", string(scanOutput))

				// Parse patched scan
				patchedVulns, err := getGoBinaryVulns(patchedScanFile)
				require.NoError(t, err, "Failed to parse patched scan")

				// Verify vulnerabilities were reduced (not all may be fixable, e.g., main module)
				t.Logf("Original vulnerabilities: %d, Patched vulnerabilities: %d",
					len(originalVulns), len(patchedVulns))
				assert.LessOrEqual(t, len(patchedVulns), len(originalVulns),
					"Patched image should have same or fewer vulnerabilities")

				// Verify specific dependency vulnerabilities were fixed
				// (main module vulnerabilities will remain as they can't be updated)
				fixedCount := 0
				for pkg := range originalVulns {
					// Skip main module vulnerabilities
					if strings.Contains(pkg, "coredns/coredns") {
						continue
					}
					if _, stillVuln := patchedVulns[pkg]; !stillVuln {
						fixedCount++
						t.Logf("Fixed vulnerability in: %s", pkg)
					}
				}
				assert.Greater(t, fixedCount, 0, "Expected at least one dependency vulnerability to be fixed")
			}

			// Cleanup patched image
			exec.Command("docker", "rmi", patchedTag).Run()
		})
	}
}

// getGoBinaryVulns extracts Go binary vulnerabilities from a Trivy scan JSON file.
func getGoBinaryVulns(scanFile string) (map[string]bool, error) {
	data, err := os.ReadFile(scanFile)
	if err != nil {
		return nil, err
	}

	var scan struct {
		Results []struct {
			Type            string `json:"Type"`
			Vulnerabilities []struct {
				PkgName string `json:"PkgName"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(data, &scan); err != nil {
		return nil, err
	}

	vulns := make(map[string]bool)
	for _, result := range scan.Results {
		if result.Type == "gobinary" {
			for _, vuln := range result.Vulnerabilities {
				vulns[vuln.PkgName] = true
			}
		}
	}

	return vulns, nil
}
