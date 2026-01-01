package golang

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed fixtures/test-images.json
var testImages []byte

type testImage struct {
	Image          string `json:"image"`
	Tag            string `json:"tag"`
	Description    string `json:"description"`
	ExpectFix      bool   `json:"expectFix"`
	SkipMainModule bool   `json:"skipMainModule"`
}

// Vulnerability defines the fields we need to uniquely identify a vulnerability.
type Vulnerability struct {
	ID      string `json:"VulnerabilityID"`
	PkgName string `json:"PkgName"`
}

// Key creates a unique identifier for a vulnerability instance.
func (v Vulnerability) Key() string {
	return fmt.Sprintf("%s|%s", v.PkgName, v.ID)
}

func TestGoBinaryPatching(t *testing.T) {
	// Download Trivy DB once before running all sub-tests.
	downloadTrivyDB(t)

	var images []testImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	for _, img := range images {
		t.Run(img.Description, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			// Build the full image reference.
			ref := img.Image + ":" + img.Tag

			// 1. Scan the original image.
			t.Log("scanning original image for baseline")
			scanResultsFile := filepath.Join(dir, "scan.json")
			vulnsBefore := scanAndParse(t, ref, scanResultsFile, img.SkipMainModule)
			require.NotEmpty(t, vulnsBefore, "expected vulnerabilities in the baseline scan")
			t.Logf("Found %d unique vulnerabilities before patching", len(vulnsBefore))

			// 2. Patch the image.
			t.Log("patching image")
			tagPatched := img.Tag + "-patched"
			copaOutput := patchImage(t, ref, tagPatched, scanResultsFile)

			// 3. Scan the patched image.
			t.Log("scanning patched image")
			patchedRef := img.Image + ":" + tagPatched
			vulnsAfter := scanAndParse(t, patchedRef, "", img.SkipMainModule)
			t.Logf("Found %d unique vulnerabilities after patching", len(vulnsAfter))

			// 4. Verify the patch was successful.
			t.Logf("Comparing vulnerabilities: Before (%d) vs After (%d)", len(vulnsBefore), len(vulnsAfter))

			if img.ExpectFix {
				assert.Less(t, len(vulnsAfter), len(vulnsBefore),
					"expected fewer vulnerabilities after patching. Before: %d, After: %d. Copa output:\n%s",
					len(vulnsBefore), len(vulnsAfter), copaOutput)
			}

			// No new vulnerabilities should have been introduced.
			for key, vuln := range vulnsAfter {
				assert.Contains(t, vulnsBefore, key, "no new vulnerabilities should be introduced. Found new vuln: %+v", vuln)
			}

			// Cleanup patched image.
			_ = exec.Command("docker", "rmi", patchedRef).Run()
		})
	}
}

func downloadTrivyDB(t *testing.T) {
	t.Helper()
	cmd := exec.Command("trivy", "image", "--download-db-only")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to download trivy db:\n%s", string(output))
}

func scanAndParse(t *testing.T, image string, outputFile string, skipMainModule bool) map[string]Vulnerability {
	t.Helper()

	if outputFile == "" {
		f, err := os.CreateTemp(t.TempDir(), "scan-*.json")
		require.NoError(t, err)
		outputFile = f.Name()
		f.Close()
	}

	args := []string{
		"trivy", "image",
		"--quiet",
		"--format=json",
		"-o=" + outputFile,
		"--pkg-types=library",
		"--ignore-unfixed",
		"--skip-db-update",
		image,
	}

	cmd := exec.Command(args[0], args[1:]...) //#nosec G204
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("trivy scan failed: %v\nOutput: %s", err, string(output))
		require.NoError(t, err, "trivy scan failed")
	}

	reportBytes, err := os.ReadFile(outputFile)
	require.NoError(t, err, "failed to read trivy report file")

	var report struct {
		Results []struct {
			Type            string          `json:"Type"`
			Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	err = json.Unmarshal(reportBytes, &report)
	require.NoError(t, err, "failed to unmarshal trivy report")

	vulns := make(map[string]Vulnerability)
	for _, result := range report.Results {
		// Only consider gobinary results.
		if result.Type != "gobinary" {
			continue
		}
		for _, v := range result.Vulnerabilities {
			// Skip main module vulnerabilities if configured.
			// Main module vulns cannot be patched without rebuilding the entire app.
			if skipMainModule && isMainModuleVuln(v.PkgName, image) {
				continue
			}
			vulns[v.Key()] = v
		}
	}

	return vulns
}

// isMainModuleVuln checks if a vulnerability is in the main module.
// Main module packages typically match the image name pattern.
func isMainModuleVuln(pkgName, image string) bool {
	// Extract the likely main module name from the image.
	// e.g., "coredns/coredns" -> "coredns"
	// e.g., "traefik" -> "traefik"
	parts := strings.Split(image, "/")
	imageName := parts[len(parts)-1]
	imageName = strings.Split(imageName, ":")[0]

	return strings.Contains(strings.ToLower(pkgName), strings.ToLower(imageName))
}

func patchImage(t *testing.T, image, tag, reportFile string) string {
	t.Helper()

	args := []string{
		"patch",
		"-i=" + image,
		"-r=" + reportFile,
		"-t=" + tag,
		"--pkg-types=os,library",
		"--enable-go-binary-rebuild",
		"--timeout=15m",
	}

	if buildkitAddr != "" {
		args = append(args, "-a="+buildkitAddr)
	}

	cmd := exec.Command(copaPath, args...) //#nosec G204
	cmd.Env = append(os.Environ(), "COPA_EXPERIMENTAL=1")
	out, err := cmd.CombinedOutput()

	require.NoError(t, err, fmt.Sprintf("Copa patch failed:\n%s", string(out)))

	return string(out)
}
