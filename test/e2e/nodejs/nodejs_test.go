package nodejs

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed fixtures/test-images.json
var testImages []byte

type testImage struct {
	Image       string `json:"image"`
	Tag         string `json:"tag"`
	Digest      string `json:"digest"`
	Description string `json:"description"`
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

func TestNodeJSPatching(t *testing.T) {
	// Download Trivy DB once before running all sub-tests.
	downloadTrivyDB(t)

	var images []testImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	for _, img := range images {
		t.Run(img.Description, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			// Build the full image reference
			ref := img.Image + ":" + img.Tag
			if img.Digest != "" {
				ref += "@" + img.Digest
			}

			// 1. Scan the original image. This generates the report for `copa patch`
			// and also gives us the baseline list of vulnerabilities.
			t.Log("scanning original image for baseline")
			scanResultsFile := filepath.Join(dir, "scan.json")
			vulnsBefore := scanAndParse(t, ref, scanResultsFile)

			if len(vulnsBefore) == 0 {
				t.Log("No fixable vulnerabilities found in original image, skipping patch test.")
				return
			}

			// 2. Patch the image using the generated report.
			t.Log("patching image")
			tagPatched := img.Tag + "-patched"
			patchImage(t, ref, tagPatched, scanResultsFile)

			// 3. Scan the newly patched image to get the list of remaining vulnerabilities.
			t.Log("scanning patched image for verification")
			patchedRef := img.Image + ":" + tagPatched
			vulnsAfter := scanAndParse(t, patchedRef, "") // No need to save this report file.

			// 4. Verify that the patch was successful and didn't introduce new issues.
			t.Logf("Comparing vulnerabilities: Before (%d) vs After (%d)", len(vulnsBefore), len(vulnsAfter))

			// Assertion 1: The number of vulnerabilities should decrease.
			assert.Less(t, len(vulnsAfter), len(vulnsBefore), "the number of vulnerabilities should be lower after patching")

			// Assertion 2: No new vulnerabilities should have been introduced.
			// Every vulnerability that exists *after* the patch must have existed *before*.
			for key, vuln := range vulnsAfter {
				assert.Contains(t, vulnsBefore, key, "no new vulnerabilities should be introduced. Found new vuln: %+v", vuln)
			}
		})
	}
}

func downloadTrivyDB(t *testing.T) {
	t.Helper()

	cmd := exec.Command("trivy", "image", "--download-db-only")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to download Trivy DB:\n%s", string(out))
}

// scanAndParse runs trivy on an image, saves the JSON report to outputFile (if provided),
// and returns a map of the found vulnerabilities for easy comparison.
func scanAndParse(t *testing.T, image string, outputFile string) map[string]Vulnerability {
	t.Helper()

	// If no output file is specified for saving, create a temporary one for parsing.
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
	cmd.Env = append(os.Environ(), "COPA_EXPERIMENTAL=1")
	_, _ = cmd.CombinedOutput()
	// We don't assert require.NoError here, as trivy will exit with a non-zero code if it finds vulns.

	// Parse the JSON report to extract vulnerabilities.
	reportBytes, err := os.ReadFile(outputFile)
	require.NoError(t, err, "failed to read trivy report file")

	var report struct {
		Results []struct {
			Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	require.NoError(t, json.Unmarshal(reportBytes, &report), "failed to unmarshal trivy report")

	// Consolidate all found vulnerabilities into a map for easy lookup.
	vulns := make(map[string]Vulnerability)
	for _, res := range report.Results {
		for _, v := range res.Vulnerabilities {
			if v.ID != "" {
				vulns[v.Key()] = v
			}
		}
	}
	return vulns
}

func patchImage(t *testing.T, image, tag, reportFile string) {
	t.Helper()

	args := []string{
		"patch",
		"-i=" + image,
		"-r=" + reportFile,
		"-t=" + tag,
		"--pkg-types=library",
		"--library-patch-level=minor",
		"--timeout=10m", // Increased timeout for potentially long npm installs
	}

	if buildkitAddr != "" {
		args = append(args, "-a="+buildkitAddr)
	}

	cmd := exec.Command(copaPath, args...) //#nosec G204
	cmd.Env = append(os.Environ(), "COPA_EXPERIMENTAL=1")
	out, err := cmd.CombinedOutput()

	require.NoError(t, err, fmt.Sprintf("Copa patch failed:\n%s", string(out)))
}
