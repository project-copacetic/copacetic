package dotnet

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

func TestDotNetSDKImagePatching(t *testing.T) {
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

			// 1. Scan the original image.
			t.Log("scanning original image for baseline")
			scanResultsFile := filepath.Join(dir, "scan.json")
			vulnsBefore := scanAndParse(t, ref, scanResultsFile)
			require.NotEmpty(t, vulnsBefore, "expected vulnerabilities in the baseline scan")
			t.Logf("Found %d unique vulnerabilities before patching", len(vulnsBefore))

			// 2. Patch the image.
			t.Log("patching image")
			tagPatched := img.Tag + "-patched"
			copaOutput := patchImage(t, ref, tagPatched, scanResultsFile)

			// 3. Scan the patched image.
			t.Log("scanning patched image")
			patchedRef := img.Image + ":" + tagPatched
			vulnsAfter := scanAndParse(t, patchedRef, "")
			t.Logf("Found %d unique vulnerabilities after patching", len(vulnsAfter))

			// 4. Verify the patch was successful
			t.Logf("Comparing vulnerabilities: Before (%d) vs After (%d)", len(vulnsBefore), len(vulnsAfter))
			assert.Less(t, len(vulnsAfter), len(vulnsBefore),
				"expected fewer vulnerabilities after patching. Before: %d, After: %d. Copa output:\n%s",
				len(vulnsBefore), len(vulnsAfter), copaOutput)

			// No new vulnerabilities should have been introduced
			for key, vuln := range vulnsAfter {
				assert.Contains(t, vulnsBefore, key, "no new vulnerabilities should be introduced. Found new vuln: %+v", vuln)
			}

			// Verify Newtonsoft.Json was patched specifically
			hasNewtonsoftVulnAfter := false
			for _, vuln := range vulnsAfter {
				if strings.Contains(vuln.PkgName, "Newtonsoft.Json") {
					hasNewtonsoftVulnAfter = true
					t.Logf("Still found Newtonsoft.Json vulnerability after patching: %s", vuln.ID)
					break
				}
			}
			assert.False(t, hasNewtonsoftVulnAfter, "expected Newtonsoft.Json vulnerabilities to be fixed after patching")
		})
	}
}

func downloadTrivyDB(t *testing.T) {
	t.Helper()
	t.Log("downloading Trivy database")
	cmd := exec.Command(
		"trivy",
		"image",
		"--download-db-only",
		"--db-repository=ghcr.io/aquasecurity/trivy-db:2,public.ecr.aws/aquasecurity/trivy-db",
	)
	cmd.Env = append(os.Environ(), "COPA_EXPERIMENTAL=1")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to download trivy db:\n%s", string(output))
}

func scanAndParse(t *testing.T, image string, outputFile string) map[string]Vulnerability {
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
	cmd.Env = append(os.Environ(), "COPA_EXPERIMENTAL=1")
	_, _ = cmd.CombinedOutput()

	reportBytes, err := os.ReadFile(outputFile)
	require.NoError(t, err, "failed to read trivy report file")

	var report struct {
		Results []struct {
			Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	err = json.Unmarshal(reportBytes, &report)
	require.NoError(t, err, "failed to unmarshal trivy report")

	vulns := make(map[string]Vulnerability)
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			vulns[v.Key()] = v
		}
	}

	return vulns
}

func patchImage(t *testing.T, image, tag, reportFile string) string {
	t.Helper()

	args := []string{
		"patch",
		"-i=" + image,
		"-r=" + reportFile,
		"-t=" + tag,
		"--pkg-types=library",
		"--library-patch-level=major",
		"--timeout=10m",
		"--debug",
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
