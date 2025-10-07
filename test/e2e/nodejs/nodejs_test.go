package nodejs

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

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

func TestNodeJSPatching(t *testing.T) {
	// Download Trivy DB once before running tests
	downloadTrivyDB(t)

	var images []testImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	for _, img := range images {
		t.Run(img.Description, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			// Build image reference
			ref := img.Image + ":" + img.Tag
			if img.Digest != "" {
				ref += "@" + img.Digest
			}

			// Scan original image
			scanResults := filepath.Join(dir, "scan.json")
			t.Log("scanning original image")
			scanImage(t, ref, scanResults, false)

			// Patch the image with the scan report
			tagPatched := img.Tag + "-patched"
			t.Log("patching image")
			patchImage(t, ref, tagPatched, scanResults)

			// Scan patched image and expect no vulnerabilities
			patchedRef := img.Image + ":" + tagPatched
			t.Log("scanning patched image")
			scanImage(t, patchedRef, "", true)
		})
	}
}

func downloadTrivyDB(t *testing.T) {
	t.Helper()

	cmd := exec.Command("trivy", "image", "--download-db-only")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to download Trivy DB:\n%s", string(out))
}

func scanImage(t *testing.T, image, outputFile string, expectNoVulns bool) {
	t.Helper()

	args := []string{
		"trivy",
		"image",
		"--quiet",
		"--pkg-types=os,library",
		"--ignore-unfixed",
		"--skip-db-update",
	}

	if outputFile != "" {
		args = append(args, "-o="+outputFile, "-f=json")
	}

	// If we expect no vulnerabilities, use --exit-code=1 to fail if any are found
	if expectNoVulns {
		args = append(args, "--exit-code=1")
	}

	args = append(args, image)

	cmd := exec.Command(args[0], args[1:]...) //#nosec G204
	cmd.Env = append(os.Environ(), "COPA_EXPERIMENTAL=1")
	out, err := cmd.CombinedOutput()

	if expectNoVulns {
		require.NoError(t, err, "Expected no vulnerabilities in patched image, but scan failed:\n%s", string(out))
	} else if outputFile != "" {
		// For initial scan, just require it created the output file
		require.FileExists(t, outputFile, "Trivy scan should create output file")
	}
}

func patchImage(t *testing.T, image, tag, reportFile string) {
	t.Helper()

	args := []string{
		"patch",
		"-i=" + image,
		"-r=" + reportFile,
		"-t=" + tag,
		"--pkg-types=os,library",
		"--timeout=5m",
	}

	if buildkitAddr != "" {
		args = append(args, "-a="+buildkitAddr)
	}

	//#nosec G204
	cmd := exec.Command(copaPath, args...)
	cmd.Env = append(os.Environ(), "COPA_EXPERIMENTAL=1")
	out, err := cmd.CombinedOutput()

	require.NoError(t, err, fmt.Sprintf("Copa patch failed:\n%s", string(out)))
}
