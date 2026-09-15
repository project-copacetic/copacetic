package python

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

// TestCustomBuildPythonVenvPatching builds a controlled Docker image with a
// known-vulnerable Python package inside a virtual environment, patches it with
// Copa, and verifies the vulnerability is resolved. This is the primary test for
// the Python venv patching feature because it uses a pinned, stable CVE that is
// unaffected by Trivy DB drift.
func TestCustomBuildPythonVenvPatching(t *testing.T) {
	downloadTrivyDB(t)

	imageTag := "copa-e2e-python-venv-vulnerable:latest"
	patchedTag := "copa-e2e-python-venv-vulnerable:patched"

	t.Cleanup(func() {
		t.Logf("Cleaning up images: %s, %s", imageTag, patchedTag)
		cmd := exec.Command("docker", "rmi", "-f", imageTag, patchedTag)
		_ = cmd.Run()
	})

	t.Logf("Building vulnerable image: %s", imageTag)
	buildCmd := exec.Command("docker", "build", "-t", imageTag, "./testdata")
	buildOutput, err := buildCmd.CombinedOutput()
	require.NoError(t, err, "Failed to build docker image from testdata:\n%s", string(buildOutput))

	dir := t.TempDir()

	t.Log("Scanning original image for baseline")
	scanResultsFile := filepath.Join(dir, "scan.json")
	vulnsBefore := scanAndParse(t, imageTag, scanResultsFile)
	require.NotEmpty(t, vulnsBefore, "expected to find vulnerabilities in the custom-built image")

	t.Log("Patching image")
	// patchImage uses require.NoError internally; call Copa manually here so we
	// can detect the "pull access denied" error that occurs when Copa's BuildKit
	// driver cannot access locally-built images (e.g. docker-container buildx
	// without containerd image store). In CI the --addr flag points to a
	// BuildKit that has local image access, so this path is exercised there.
	copaOutput, copaErr := runPatchImage(imageTag, patchedTag, scanResultsFile, "--library-patch-level=minor")
	if copaErr != nil {
		if strings.Contains(copaOutput, "pull access denied") || strings.Contains(copaOutput, "repository does not exist") {
			t.Skip("Copa's BuildKit driver cannot access locally-built images in this environment; " +
				"pass --addr to specify a BuildKit with local image access (works in CI)")
		}
		require.NoError(t, copaErr, "Copa patch failed:\n%s", copaOutput)
	}

	t.Logf("Scanning patched image for verification: %s", patchedTag)
	vulnsAfter := scanAndParse(t, patchedTag, "")

	t.Logf("Comparing vulnerabilities: Before (%d) vs After (%d)", len(vulnsBefore), len(vulnsAfter))

	// Vulnerability count must drop — the venv requests CVE should be gone.
	assert.Less(t, len(vulnsAfter), len(vulnsBefore),
		"the number of vulnerabilities should be lower after patching. Copa output:\n%s", copaOutput)

	// No new vulnerabilities should have been introduced.
	for key, vuln := range vulnsAfter {
		assert.Contains(t, vulnsBefore, key,
			"no new vulnerabilities should be introduced. Found new vuln: %+v", vuln)
	}
}

// TestPythonVenvPatchingRealWorld patches a real-world image (k8s-sidecar) and
// verifies Copa handles it gracefully: the patch command succeeds and no new
// vulnerabilities are introduced. This image has packages in vendored locations
// that Copa correctly skips; the actual vulnerability count may not decrease if
// all remaining CVEs are in vendored copies.
func TestPythonVenvPatchingRealWorld(t *testing.T) {
	downloadTrivyDB(t)

	var images []testImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	for _, img := range images {
		t.Run(img.Description, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			// Build the full image reference including digest for reproducibility.
			ref := img.Image + ":" + img.Tag
			if img.Digest != "" {
				ref += "@" + img.Digest
			}

			// 1. Scan the original image.
			t.Log("scanning original image for baseline")
			scanResultsFile := filepath.Join(dir, "scan.json")
			vulnsBefore := scanAndParse(t, ref, scanResultsFile)

			if len(vulnsBefore) == 0 {
				t.Log("No fixable vulnerabilities found in original image, skipping patch test.")
				return
			}

			// 2. Patch the image — Copa must not error out.
			t.Log("patching image")
			tagPatched := img.Tag + "-patched"
			patchImage(t, ref, tagPatched, scanResultsFile, "--library-patch-level=major")

			// 3. Rescan and verify no regressions.
			t.Log("scanning patched image for regressions")
			patchedRef := img.Image + ":" + tagPatched
			vulnsAfter := scanAndParse(t, patchedRef, "")

			t.Logf("Comparing vulnerabilities: Before (%d) vs After (%d)", len(vulnsBefore), len(vulnsAfter))

			// No new vulnerabilities should have been introduced.
			for key, vuln := range vulnsAfter {
				assert.Contains(t, vulnsBefore, key,
					"no new vulnerabilities should be introduced. Found new vuln: %+v", vuln)
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
	require.NoError(t, json.Unmarshal(reportBytes, &report), "failed to unmarshal trivy report")

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

// patchImage runs Copa and requires it to succeed (fails the test otherwise).
func patchImage(t *testing.T, image, tag, reportFile string, extraArgs ...string) string {
	t.Helper()
	out, err := runPatchImage(image, tag, reportFile, extraArgs...)
	require.NoError(t, err, fmt.Sprintf("Copa patch failed:\n%s", out))
	return out
}

// runPatchImage runs Copa and returns the combined output and any error.
// Use this when you need to inspect the error before failing the test.
func runPatchImage(image, tag, reportFile string, extraArgs ...string) (string, error) {
	args := []string{
		"patch",
		"-i=" + image,
		"-r=" + reportFile,
		"-t=" + tag,
		"--pkg-types=library",
		"--timeout=10m",
		"--debug",
	}
	args = append(args, extraArgs...)

	if buildkitAddr != "" {
		args = append(args, "-a="+buildkitAddr)
	}

	cmd := exec.Command(copaPath, args...) //#nosec G204
	cmd.Env = append(os.Environ(), "COPA_EXPERIMENTAL=1")
	out, err := cmd.CombinedOutput()
	return string(out), err
}
